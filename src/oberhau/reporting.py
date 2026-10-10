from __future__ import annotations

import html
import json
from pathlib import Path
from threading import Event
from urllib.parse import quote

from oberhau import __version__
from oberhau.core import DraftText, Finding, OberhauError, Status, now
from oberhau.database import Database
from oberhau.ollama import Ollama
from oberhau.security import redact


def generate(
    db: Database,
    finding_id: int,
    language: str = "en",
    ai: bool = False,
    cancel: Event | None = None,
) -> tuple[int, str]:
    record = db.finding(finding_id)
    finding: Finding = record["finding"]
    if language not in {"en", "pt-BR"}:
        raise OberhauError("Unsupported report language")
    portuguese = language == "pt-BR"
    generator = "deterministic"
    warning = ""
    text = DraftText(
        summary=finding.title,
        explanation=finding.explanation,
        remediation="Review input handling and access boundaries; apply a fix and add a regression test.",
        limitations="Static evidence alone does not establish reachability, exploitability, novelty or bounty eligibility.",
    )
    if ai:
        evidence = {
            "title": finding.title,
            "path": finding.path,
            "line": finding.line,
            "status": record["status"],
            "explanation": finding.explanation,
            "context": finding.context[:6000],
            "notes": record["notes"][:2000],
        }
        try:
            text = Ollama(
                db.setting("ollama_url", "http://127.0.0.1:11434"),
                db.setting("ollama_model", "qwen3.5:4b"),
            ).draft(evidence, language, cancel)
            generator = "ollama:unverified-draft"
        except OberhauError as error:
            warning = str(error)
            generator = "deterministic:fallback"
    validations = db.query("SELECT result FROM validations WHERE finding_id=?", (finding_id,))
    reviewed = record["status"] in {Status.VERIFIED, Status.READY} and bool(record["notes"].strip())
    readiness = (
        "Ready for Human Review"
        if reviewed
        else "Evidence incomplete — human investigation required"
    )
    labels = {
        "summary": "Resumo" if portuguese else "Summary",
        "evidence": "Evidências registradas" if portuguese else "Recorded evidence",
        "explanation": "Explicação provisória" if portuguese else "Provisional explanation",
        "remediation": "Correção sugerida" if portuguese else "Suggested remediation",
        "limits": "Limitações" if portuguese else "Limitations",
    }
    content = f"""# {finding.title}

> {readiness}
> {"Rascunho para revisão humana. Sem submissão automática." if portuguese else "Draft for human review. No automatic submission."}

## {labels["evidence"]}

- Finding: {finding_id}; project: {record["project_id"]}
- Scanner / rule: {finding.scanner} / {finding.rule}
- Location: `{finding.path}:{finding.line}-{finding.end_line}`
- State: {record["status"]}
- Severity (scanner estimate): {finding.severity}; detection confidence: {finding.confidence:.0%}
- CWE: {", ".join(finding.cwe) or "Not provided"}
- Advisories: {", ".join(finding.advisories) or "Not provided"}
- Snapshot SHA-256: {finding.evidence.get("source_sha256", "Not recorded")}
- Scan: {finding.evidence.get("scan", "Not recorded")}
- First seen: {record["first_seen"]}; last seen: {record["last_seen"]}

```text
{finding.context.replace("```", "[code delimiter]")}
```

## {labels["summary"]}

{text.summary}

## {labels["explanation"]}

{text.explanation}

## Human observations / reproduction

{record["notes"] or "No human observations recorded. Preconditions, expected behavior, observed behavior and demonstrated impact require investigation."}

```json
{json.dumps([json.loads(v["result"]) for v in validations], indent=2, ensure_ascii=False)}
```

## {labels["remediation"]}

{text.remediation}

## {labels["limits"]}

{text.limitations}

Generator: {generator}. AI prose, when present, is unverified and never changes recorded evidence.
{warning}
"""
    content = redact(content)
    report_id = db.execute(
        "INSERT INTO reports(finding_id,content,language,generator,created) VALUES(?,?,?,?,?)",
        (finding_id, content, language, generator, now()),
    )
    db.audit("report.generate", {"id": report_id, "finding": finding_id, "generator": generator})
    return report_id, content


def export(db: Database, report_id: int, destination: Path, content: str | None = None) -> None:
    rows = db.query("SELECT * FROM reports WHERE id=?", (report_id,))
    if not rows:
        raise OberhauError("Report does not exist")
    report = rows[0]
    body = redact(content if content is not None else report["content"])
    if destination.suffix.lower() == ".html":
        output = (
            '<!doctype html><html lang="en"><meta charset="utf-8"><title>Oberhau report</title><body><pre style="white-space:pre-wrap">'
            + html.escape(body)
            + "</pre></body></html>"
        )
    elif destination.suffix.lower() == ".json":
        output = json.dumps(
            {
                "report": report_id,
                "finding": report["finding_id"],
                "content": body,
                "generator": report["generator"],
                "language": report["language"],
            },
            indent=2,
        )
    elif destination.suffix.lower() == ".sarif":
        finding = db.finding(report["finding_id"])["finding"]
        output = json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Oberhau", "version": __version__}},
                        "results": [
                            {
                                "ruleId": finding.rule,
                                "message": {"text": finding.title},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": quote(finding.path)},
                                            "region": {"startLine": finding.line},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
            indent=2,
        )
    elif destination.suffix.lower() == ".md":
        output = body
    else:
        raise OberhauError("Choose .md, .html, .json or .sarif")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(output, encoding="utf-8")
    if content is not None and body != report["content"]:
        db.execute(
            "INSERT INTO reports(finding_id,content,language,generator,created) VALUES(?,?,?,?,?)",
            (report["finding_id"], body, report["language"], "human-edit", now()),
        )
    db.audit("report.export", {"id": report_id, "destination": str(destination)})
