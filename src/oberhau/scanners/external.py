from __future__ import annotations

import json
import tempfile
from pathlib import Path
from threading import Event
from typing import Any

from oberhau.core import Finding, OberhauError
from oberhau.security import ProcessRunner, confined, redact

TOOLS = {
    "semgrep": {
        "license": "LGPL-2.1 (engine); bundled rules MIT",
        "network": False,
        "categories": ["SAST"],
        "instructions": "Install semgrep in a separate trusted Python environment; add Scripts to PATH.",
    },
    "gitleaks": {
        "license": "MIT",
        "network": False,
        "categories": ["secrets"],
        "instructions": "Install verified Windows binary from github.com/gitleaks/gitleaks/releases and add to PATH.",
    },
    "osv-scanner": {
        "license": "Apache-2.0",
        "network": True,
        "categories": ["dependencies"],
        "instructions": "Install OSV-Scanner v2 Windows binary. Offline scans require predownloaded OSV databases.",
    },
    "trivy": {
        "license": "Apache-2.0",
        "network": True,
        "categories": ["dependencies", "configuration"],
        "instructions": "Install verified Trivy Windows binary; cached vulnerability database required offline.",
    },
}


def location(root: Path, raw: str) -> str:
    value = Path(raw)
    if value.is_absolute():
        try:
            relative = value.resolve().relative_to(root.resolve()).as_posix()
        except ValueError as error:
            raise OberhauError("Scanner reported a path outside its project") from error
    else:
        relative = raw.replace("\\", "/").removeprefix("./")
    confined(root, relative)
    return relative


def parse(tool: str, payload: str, root: Path) -> list[Finding]:
    try:
        data = json.loads(payload)
        findings: list[Finding] = []
        if tool == "semgrep":
            if not isinstance(data, dict) or "results" not in data:
                raise ValueError("Missing results")
            for row in data["results"]:
                extra = row["extra"]
                metadata = extra.get("metadata", {})
                cwe = metadata.get("cwe", [])
                if isinstance(cwe, str):
                    cwe = [cwe]
                findings.append(
                    Finding(
                        scanner=tool,
                        rule=row["check_id"],
                        title=redact(extra["message"]),
                        category="SAST",
                        path=location(root, row["path"]),
                        line=row["start"]["line"],
                        end_line=row["end"]["line"],
                        severity={"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
                            extra.get("severity"), "medium"
                        ),
                        cwe=cwe,
                        context=redact(extra.get("lines", "")),
                        confidence=0.7,
                    )
                )
        elif tool == "gitleaks":
            if not isinstance(data, list):
                raise ValueError("Expected findings array")
            for row in data:
                # Match and Secret are deliberately discarded even if the tool ignored --redact.
                findings.append(
                    Finding(
                        scanner=tool,
                        rule=row["RuleID"],
                        title="Possible exposed credential (redacted)",
                        category="secrets",
                        path=location(root, row["File"]),
                        line=row["StartLine"],
                        end_line=row.get("EndLine", row["StartLine"]),
                        severity="high",
                        cwe=["CWE-798"],
                        context="[Secret and match withheld]",
                        evidence={"commit": row.get("Commit", "")},
                    )
                )
        elif tool == "osv-scanner":
            if not isinstance(data, dict) or "results" not in data:
                raise ValueError("Missing results")
            for group in data["results"]:
                for package in group.get("packages", []):
                    item = package["package"]
                    for advisory in package.get("vulnerabilities", []):
                        findings.append(
                            Finding(
                                scanner=tool,
                                rule=advisory["id"],
                                title=f"{item['name']} {item.get('version', '')}: {advisory['id']}",
                                category="dependencies",
                                path=location(root, group["source"]["path"]),
                                advisories=[advisory["id"], *advisory.get("aliases", [])],
                                confidence=0.9,
                                explanation="Known package advisory. Reachability and demonstrated impact have not been established.",
                                evidence={
                                    "package": item,
                                    "affected": advisory.get("affected", []),
                                },
                            )
                        )
        elif tool == "trivy":
            if not isinstance(data, dict) or "SchemaVersion" not in data:
                raise ValueError("Missing schema version")
            for group in data.get("Results", []):
                for item in group.get("Vulnerabilities", []) or []:
                    findings.append(
                        Finding(
                            scanner=tool,
                            rule=item["VulnerabilityID"],
                            category="dependencies",
                            title=f"{item['PkgName']}: {item['VulnerabilityID']}",
                            path=location(root, group["Target"]),
                            advisories=[item["VulnerabilityID"]],
                            severity=item.get("Severity", "medium").lower(),
                            evidence={
                                "package": item["PkgName"],
                                "version": item.get("InstalledVersion"),
                                "fixed": item.get("FixedVersion"),
                            },
                        )
                    )
                for item in group.get("Misconfigurations", []) or []:
                    findings.append(
                        Finding(
                            scanner=tool,
                            rule=item["ID"],
                            category="configuration",
                            title=redact(item["Title"]),
                            path=location(root, group["Target"]),
                            severity=item.get("Severity", "medium").lower(),
                            explanation=redact(item.get("Description", "Review required")),
                        )
                    )
        else:
            raise ValueError("Unsupported scanner")
        return findings
    except (ValueError, TypeError, KeyError) as error:
        raise OberhauError(f"{tool}: malformed or unsupported JSON: {error}") from error


class ExternalScanner:
    def __init__(self, identifier: str, runner: ProcessRunner, rules: Path):
        if identifier not in TOOLS:
            raise OberhauError("Scanner not registered")
        self.identifier, self.runner, self.rules = identifier, runner, rules

    def scan(self, root: Path, cancel: Event) -> list[Finding]:
        tool = self.identifier
        work = root.parent.parent / "tmp"
        work.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="oberhau-tool-", dir=work) as temporary:
            temp = Path(temporary)
            if tool == "semgrep":
                # Trusted explicit rules; no auto registry, no repository configuration.
                args = [
                    "scan",
                    "--config",
                    str(self.rules),
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--no-git-ignore",
                    "--jobs",
                    str(self.runner.limits.parallelism),
                    str(root),
                ]
                output = self.runner.run(tool, args, temp, cancel)
                raw = json.loads(output)
                if raw.get("errors"):
                    raise OberhauError(
                        "Semgrep reported incomplete coverage: "
                        + redact(json.dumps(raw["errors"])[:4000])
                    )
            elif tool == "gitleaks":
                report = temp / "gitleaks.json"
                # Empty trusted config invokes tool defaults, without reading repository .gitleaks.toml.
                config = temp / "config.toml"
                config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
                self.runner.run(
                    tool,
                    [
                        "dir",
                        str(root),
                        "--config",
                        str(config),
                        "--redact=100",
                        "--report-format=json",
                        "--report-path",
                        str(report),
                        "--no-banner",
                    ],
                    temp,
                    cancel,
                    (0, 1),
                )
                if (
                    not report.exists()
                    or report.stat().st_size > self.runner.limits.max_output_bytes
                ):
                    raise OberhauError("Gitleaks report missing or oversized")
                output = report.read_text(encoding="utf-8")
            elif tool == "osv-scanner":
                config = temp / "osv.toml"
                config.write_text("", encoding="utf-8")
                output = self.runner.run(
                    tool,
                    [
                        "scan",
                        "source",
                        "-r",
                        str(root),
                        "--format=json",
                        "--offline",
                        "--config",
                        str(config),
                    ],
                    temp,
                    cancel,
                    (0, 1),
                )
            else:
                config = temp / "trivy.yaml"
                config.write_text("{}", encoding="utf-8")
                output = self.runner.run(
                    tool,
                    [
                        "fs",
                        "--config",
                        str(config),
                        "--format=json",
                        "--scanners=vuln,misconfig",
                        "--skip-db-update",
                        "--offline-scan",
                        str(root),
                    ],
                    temp,
                    cancel,
                )
            return parse(tool, output, root)


def capabilities(runner: ProcessRunner) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {
            "scanner": "builtin",
            "installed": True,
            "version": "0.1.0",
            "path": "bundled",
            "license": "MIT",
            "network": False,
            "active": False,
            "categories": ["Python AST", "secrets", "configuration"],
        }
    ]
    for tool, meta in TOOLS.items():
        binary = runner.tools.get(tool)
        status: dict[str, Any] = {
            "scanner": tool,
            "installed": bool(binary),
            "path": binary,
            "version": None,
            "active": False,
            **meta,
        }
        if binary:
            try:
                flag = "version" if tool == "gitleaks" else "--version"
                status["version"] = redact(
                    runner.run(tool, [flag], Path(tempfile.gettempdir()), Event())
                ).strip()[:300]
            except OberhauError as error:
                status["installed"] = False
                status["error"] = str(error)
        rows.append(status)
    return rows
