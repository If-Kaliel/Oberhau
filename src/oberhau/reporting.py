from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from threading import Event
from urllib.parse import quote

from oberhau import __version__
from oberhau.core import DraftText, Finding, Limits, OberhauError, Status, now
from oberhau.database import Database
from oberhau.ollama import Ollama
from oberhau.security import confined, redact


def report_evidence(db: Database, finding_id: int) -> dict:
    record = db.finding(finding_id)
    finding = record["finding"]
    source_state, analysis = "unavailable", None
    try:
        home = db.path.parent.resolve()
        root = Path(finding.evidence.get("snapshot", ""))
        relative = root.relative_to(home)
        if len(relative.parts) != 2 or relative.parts[0] != "projects":
            raise OberhauError("Invalid snapshot")
        root = confined(home, relative.as_posix())
        path = confined(root, finding.path)
        maximum = Limits.model_validate(db.setting("limits", {})).max_file_bytes
        with path.open("rb") as source:
            content = source.read(maximum + 1)
        if len(content) > maximum:
            raise OberhauError("Source exceeds configured limit")
        source_state = (
            "verified"
            if hashlib.sha256(content).hexdigest() == finding.evidence.get("source_sha256")
            else "changed"
        )
        if source_state == "verified" and path.suffix == ".py":
            from oberhau.python_analysis import source_trace

            analysis = source_trace(
                content.decode("utf-8", errors="replace"), finding.line, finding.rule
            )
    except (OSError, ValueError, OberhauError):
        pass
    validation = [
        json.loads(row["result"])
        for row in db.query("SELECT result FROM validations WHERE finding_id=?", (finding_id,))
    ]
    reviewed = record["status"] in {Status.VERIFIED, Status.READY} and bool(record["notes"].strip())
    return {
        "source_integrity": source_state,
        "human_review_recorded": reviewed,
        "local_reproduction_recorded": any(item.get("passed") for item in validation),
        "ready_for_human_review": reviewed and source_state == "verified",
        "python_analysis": analysis,
        "validations": validation,
        "remaining_manual_checks": [
            "Preconditions and attacker control",
            "Expected and observed behavior",
            "Demonstrated impact",
            "Policy eligibility and disclosure requirements",
        ],
    }


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
    quality = report_evidence(db, finding_id)
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
            "advisories": finding.advisories,
            "source_integrity": quality["source_integrity"],
            "python_analysis": quality["python_analysis"],
            "validations": quality["validations"][:3],
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
    readiness = (
        "Ready for Human Review"
        if quality["ready_for_human_review"]
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
- Source integrity at generation: {quality["source_integrity"]}
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

## {"Verificações de evidência" if portuguese else "Evidence checks"}

```json
{json.dumps({key: value for key, value in quality.items() if key not in {"validations", "python_analysis"}}, indent=2, ensure_ascii=False)}
```

{("```json\n" + json.dumps(quality["python_analysis"], indent=2, ensure_ascii=False) + "\n```") if quality["python_analysis"] else ""}

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
