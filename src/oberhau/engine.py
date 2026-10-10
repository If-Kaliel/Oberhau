from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from threading import Event

from oberhau.core import Cancelled, Finding, Limits, OberhauError, now
from oberhau.database import Database
from oberhau.ingestion import Ingestion, file_index
from oberhau.plugins import Registry
from oberhau.scanners.builtin import BuiltinScanner
from oberhau.scanners.external import ExternalScanner
from oberhau.security import ProcessRunner, redact, redact_source

ASSETS = Path(__file__).parent / "assets"
PROFILES = {
    "quick": ("Bundled Python AST, literal secrets, and configuration heuristics.", ["builtin"]),
    "standard": (
        "Bundled checks and Semgrep with trusted bundled rules, if installed.",
        ["builtin", "semgrep"],
    ),
    "deep": (
        "All available offline adapters; OSV/Trivy need existing databases.",
        ["builtin", "semgrep", "gitleaks", "osv-scanner", "trivy"],
    ),
    "changed": (
        "Bundled checks on modified files since last completed scan. External scanners excluded.",
        ["builtin"],
    ),
    "secrets": (
        "Literal-secret heuristics and installed Gitleaks on the snapshot, excluding Git history.",
        ["builtin", "gitleaks"],
    ),
    "configuration": (
        "Bundled debug/privilege checks and installed Trivy offline analysis.",
        ["builtin", "trivy"],
    ),
    "dependencies": (
        "Installed OSV-Scanner v2 and Trivy, using cached databases only.",
        ["osv-scanner", "trivy"],
    ),
}


@contextmanager
def project_lock(home: Path, project_id: int) -> Iterator[None]:
    lockdir = home / "locks"
    lockdir.mkdir(exist_ok=True)
    with (lockdir / f"{project_id}.lock").open("a+b") as handle:
        handle.write(b"0")
        handle.flush()
        handle.seek(0)
        try:
            if __import__("os").name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise OberhauError("A scan is already running for this project") from error
        try:
            yield
        finally:
            handle.seek(0)
            if __import__("os").name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class Engine:
    def __init__(self, home: Path):
        home = home.resolve()
        self.home = home
        home.mkdir(parents=True, exist_ok=True)
        self.db = Database(home / "oberhau.sqlite3")
        self.limits = Limits.model_validate(self.db.setting("limits", {}))
        self.ingestion = Ingestion(self.db, home, self.limits)
        self.registry = Registry()
        self.registry.register(BuiltinScanner())

    def scan(
        self,
        project_id: int,
        profile: str = "standard",
        cancel: Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> int:
        if profile not in PROFILES:
            raise OberhauError("Unknown scan profile")
        cancel = cancel or Event()
        progress = progress or (lambda message: logging.getLogger("oberhau").info(redact(message)))
        project = self.ingestion.project(project_id)
        root = Path(project["root"])
        started = time.monotonic()
        with project_lock(self.home, project_id):
            self.db.execute(
                "UPDATE scans SET status='interrupted',finished=? WHERE project_id=? AND status='running'",
                (now(), project_id),
            )
            scan_id = self.db.execute(
                "INSERT INTO scans(project_id,profile,status,started,commit_hash) VALUES(?,?,'running',?,?)",
                (project_id, profile, now(), json.loads(project["metadata"]).get("commit")),
            )
            errors: list[str] = []
            status = "completed"
            successes = 0

            def scanner_progress(message: str) -> None:
                if "Python parse error" in message:
                    errors.append(redact(message))
                progress(message)

            try:
                progress(f"Scan #{scan_id}: indexing managed snapshot")
                manifest = file_index(root, self.limits, cancel)
                paths = list(manifest)
                if profile == "changed":
                    previous = self.db.query(
                        "SELECT manifest FROM scans WHERE project_id=? AND status='completed' AND id<>? ORDER BY id DESC LIMIT 1",
                        (project_id, scan_id),
                    )
                    baseline = json.loads(previous[0]["manifest"]) if previous else {}
                    paths = [p for p in paths if baseline.get(p) != manifest[p]]
                    progress(
                        f"Incremental scope: {len(paths)} changed files; {len(set(baseline) - set(manifest))} removed"
                    )
                self.db.execute(
                    "UPDATE scans SET file_count=?,manifest=? WHERE id=?",
                    (len(paths), json.dumps(manifest), scan_id),
                )
                runner = ProcessRunner(self.limits)
                selected = PROFILES[profile][1]
                categories = [profile] if profile in {"secrets", "configuration"} else None
                jobs: dict[str, Callable[[], list[Finding]]] = {}
                for name in selected:
                    if name in self.registry.plugins:
                        plugin = self.registry.plugins[name]
                        jobs[name] = lambda p=plugin: p.scan(
                            root, paths, cancel, self.limits, scanner_progress, categories
                        )
                    elif name in runner.tools:
                        adapter = ExternalScanner(name, runner, ASSETS / "rules.yaml")
                        jobs[name] = lambda a=adapter: a.scan(root, cancel)
                    else:
                        errors.append(f"{name}: not installed; skipped")
                        progress(errors[-1])
                if not jobs:
                    raise OberhauError("No requested scanner is installed")
                with ThreadPoolExecutor(
                    max_workers=self.limits.parallelism, thread_name_prefix="oberhau-scan"
                ) as pool:
                    futures = {pool.submit(job): name for name, job in jobs.items()}
                    for future in as_completed(futures):
                        name = futures[future]
                        if cancel.is_set():
                            raise Cancelled()
                        try:
                            findings = future.result()
                            successes += 1
                            for finding in findings:
                                finding.evidence.update(
                                    {
                                        "source_sha256": manifest.get(finding.path),
                                        "snapshot": str(root),
                                        "scan": scan_id,
                                    }
                                )
                                self.db.save_finding(project_id, scan_id, finding)
                            progress(f"{name}: completed, {len(findings)} warnings")
                        except Cancelled:
                            cancel.set()
                            raise
                        except Exception as error:
                            errors.append(redact(f"{name}: {error}"))
                            progress(errors[-1])
                if errors:
                    status = "partial" if successes else "failed"
                progress(f"Scan #{scan_id}: {status}. Findings require review.")
            except Cancelled:
                status = "cancelled"
                progress(f"Scan #{scan_id}: cancelled; completed observations retained")
            except Exception as error:
                status = "failed"
                errors.append(redact(str(error)))
                progress(errors[-1])
            finally:
                self.db.execute(
                    "UPDATE scans SET status=?,finished=?,errors=?,duration=? WHERE id=?",
                    (status, now(), json.dumps(errors), time.monotonic() - started, scan_id),
                )
                self.db.audit("scan.finish", {"id": scan_id, "status": status, "errors": errors})
            return scan_id

    def investigate(self, finding_id: int) -> dict:
        record = self.db.finding(finding_id)
        finding: Finding = record["finding"]
        from oberhau.security import confined

        snapshot = Path(finding.evidence["snapshot"])
        path = confined(snapshot, finding.path)
        import hashlib

        content = path.read_bytes()
        unchanged = hashlib.sha256(content).hexdigest() == finding.evidence.get("source_sha256")
        lines = redact_source(content.decode("utf-8", errors="replace")).splitlines()
        context = redact(
            "\n".join(
                f"{i + 1:>5}  {line}"
                for i, line in enumerate(lines)
                if max(0, finding.line - 5) <= i < finding.end_line + 4
            )
        )
        related = self.db.query(
            "SELECT id,data,status FROM findings WHERE project_id=? AND id<>? AND json_extract(data,'$.path')=?",
            (record["project_id"], finding_id, finding.path),
        )
        return {
            "id": finding_id,
            "status": record["status"],
            "source_unchanged": unchanged,
            "context": context,
            "related_ids": [r["id"] for r in related],
            "observations": self.db.query(
                "SELECT scan_id,data FROM observations WHERE finding_id=?", (finding_id,)
            ),
            "questions": [
                "Can attacker-controlled input reach the flagged operation?",
                "Which authentication, authorization or validation controls apply?",
                "Can a safe isolated regression demonstrate impact and remediation?",
            ],
            "notes": record["notes"],
        }
