from __future__ import annotations

import difflib
import hashlib
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
from oberhau.repositories import GitRepositories
from oberhau.scanners.builtin import BuiltinScanner
from oberhau.scanners.external import ExternalScanner
from oberhau.security import ProcessRunner, confined, redact, redact_source, source_lines
from oberhau.storage import storage_operation, store_lock

ASSETS = Path(__file__).parent / "assets"
PROFILES = {
    "research": (
        "Offline builtin scan, framework syntax index, contextual hypotheses and evidence graph.",
        ["builtin"],
    ),
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
        with store_lock(home):
            self.db = Database(home / "oberhau.sqlite3")
            # The exclusive store lock proves no cooperating scan/import/backup is alive.
            # Surface recovery on startup, even before another scan of the same project.
            with self.db.connect() as connection:
                for table in ("research_runs", "scanner_runs", "scans"):
                    connection.execute(
                        f"UPDATE {table} SET status='interrupted',finished=? WHERE status IN ('running','pending')",
                        (now(),),
                    )
            self.limits = Limits.model_validate(self.db.setting("limits", {}))
            self.ingestion = Ingestion(self.db, home, self.limits)
        self.registry = Registry()
        self.registry.register(BuiltinScanner())

    def repositories(self) -> GitRepositories:
        return GitRepositories(self.ingestion)

    @storage_operation
    def refresh_project(
        self,
        project_id: int,
        cancel: Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        project = self.ingestion.project(project_id)
        if json.loads(project["metadata"]).get("source_kind") == "git":
            self.repositories().refresh(project_id, cancel, progress)
        else:
            self.ingestion.refresh(project_id, cancel)

    def managed_snapshot(self, value: str) -> Path:
        path = Path(value)
        try:
            relative = path.relative_to(self.home)
        except ValueError as error:
            raise OberhauError("Snapshot is outside managed project storage") from error
        if len(relative.parts) != 2 or relative.parts[0] != "projects":
            raise OberhauError("Invalid managed snapshot root")
        root = confined(self.home, relative.as_posix())
        if not root.is_dir():
            raise OberhauError("Managed source snapshot is unavailable")
        return root

    def compare_source(self, project_id: int, relative: str) -> dict:
        project = self.ingestion.project(project_id)
        metadata = json.loads(project["metadata"])
        if not metadata.get("previous_snapshot"):
            raise OberhauError("Refresh the project first to retain a comparison baseline")
        before, after = metadata["previous_manifest"], metadata["manifest"]
        if relative not in before and relative not in after:
            raise OberhauError("File is not present in the retained manifests")
        old_root = self.managed_snapshot(str(confined(self.home, metadata["previous_snapshot"])))
        new_root = self.managed_snapshot(project["root"])

        def content(root, expected):
            if expected is None:
                return b"", True
            path = confined(root, relative)
            with path.open("rb") as source:
                data = source.read(self.limits.max_file_bytes + 1)
            if len(data) > self.limits.max_file_bytes:
                raise OberhauError("Comparison file exceeds configured size limit")
            return data, hashlib.sha256(data).hexdigest() == expected

        old, old_valid = content(old_root, before.get(relative))
        new, new_valid = content(new_root, after.get(relative))
        lines = difflib.unified_diff(
            redact_source(old.decode("utf-8", errors="replace")).splitlines(keepends=True),
            redact_source(new.decode("utf-8", errors="replace")).splitlines(keepends=True),
            fromfile="previous/" + relative,
            tofile="current/" + relative,
            n=4,
        )
        text = "".join(lines)
        return {
            "project": project_id,
            "path": relative,
            "previous_commit": metadata.get("previous_commit"),
            "commit": metadata.get("commit"),
            "source_integrity": old_valid and new_valid,
            "diff": text[:50000],
            "truncated": len(text) > 50000,
        }

    @storage_operation
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
        root = self.managed_snapshot(project["root"])
        started = time.monotonic()
        with project_lock(self.home, project_id):
            self.db.execute(
                "UPDATE research_runs SET status='interrupted',finished=? WHERE project_id=? AND status='running'",
                (now(), project_id),
            )
            self.db.execute(
                "UPDATE scanner_runs SET status='interrupted',finished=? WHERE status IN ('pending','running') AND scan_id IN (SELECT id FROM scans WHERE project_id=? AND status='running')",
                (now(), project_id),
            )
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
            selected = PROFILES[profile][1]
            run_ids = {
                name: self.db.execute(
                    "INSERT INTO scanner_runs(scan_id,scanner,status) VALUES(?,?,'pending')",
                    (scan_id, name),
                )
                for name in selected
            }
            job_errors = {name: [] for name in selected}

            def scanner_progress(name: str, message: str) -> None:
                if "Python parse error" in message:
                    job_errors[name].append(redact(message))
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
                runner = ProcessRunner(self.limits, home=self.home)
                categories = [profile] if profile in {"secrets", "configuration"} else None
                jobs: dict[str, Callable[[], list[Finding]]] = {}
                adapters = {}
                provenance = {}
                for name in selected:
                    if name in self.registry.plugins:
                        plugin = self.registry.plugins[name]
                        provenance[name] = {
                            "version": plugin.version,
                            "license": plugin.license,
                            "bundled": name == "builtin",
                        }
                        jobs[name] = lambda p=plugin, n=name: p.scan(
                            root,
                            paths,
                            cancel,
                            self.limits,
                            lambda text: scanner_progress(n, text),
                            categories,
                        )
                    elif name in runner.tools:
                        adapter = ExternalScanner(name, runner, ASSETS / "rules.yaml", profile)
                        adapters[name] = adapter
                        jobs[name] = lambda a=adapter: a.scan(root, cancel)
                    else:
                        message = runner.tool_errors.get(name, f"{name}: not installed; skipped")
                        errors.append(message)
                        self.db.execute(
                            "UPDATE scanner_runs SET status='unavailable',finished=?,errors=? WHERE id=?",
                            (now(), json.dumps([message]), run_ids[name]),
                        )
                        progress(errors[-1])
                if not jobs:
                    raise OberhauError("No requested scanner is installed")

                def run_job(name: str, job: Callable) -> tuple[str, list[str]]:
                    run_started = time.monotonic()
                    self.db.execute(
                        "UPDATE scanner_runs SET status='running',started=? WHERE id=?",
                        (now(), run_ids[name]),
                    )
                    run_status, count = "completed", 0
                    try:
                        if cancel.is_set():
                            raise Cancelled()
                        findings = job()
                        count = len(findings)
                        for finding in findings:
                            if cancel.is_set():
                                raise Cancelled()
                            finding.evidence.update(
                                {
                                    "source_sha256": manifest.get(finding.path),
                                    "snapshot": str(root),
                                    "scan": scan_id,
                                }
                            )
                            self.db.save_finding(project_id, scan_id, finding)
                        if job_errors[name]:
                            run_status = "partial"
                    except Cancelled:
                        run_status = "cancelled"
                        cancel.set()
                    except Exception as error:
                        run_status = "failed"
                        job_errors[name].append(redact(f"{name}: {error}"))
                    finally:
                        info = (
                            adapters[name].last_provenance
                            if name in adapters
                            else provenance.get(name, {})
                        )
                        self.db.execute(
                            "UPDATE scanner_runs SET status=?,finished=?,duration=?,findings=?,errors=?,provenance=? WHERE id=?",
                            (
                                run_status,
                                now(),
                                time.monotonic() - run_started,
                                count,
                                json.dumps(job_errors[name]),
                                json.dumps(info),
                                run_ids[name],
                            ),
                        )
                    progress(f"{name}: {run_status}, {count} warnings")
                    return run_status, job_errors[name]

                with ThreadPoolExecutor(
                    max_workers=self.limits.parallelism, thread_name_prefix="oberhau-scan"
                ) as pool:
                    futures = {pool.submit(run_job, name, job): name for name, job in jobs.items()}
                    for future in as_completed(futures):
                        if cancel.is_set():
                            raise Cancelled()
                        run_status, run_errors = future.result()
                        if run_status in {"completed", "partial"}:
                            successes += 1
                        errors.extend(run_errors)
                if errors:
                    status = "partial" if successes else "failed"
                if profile == "research":
                    from oberhau.research import run_research

                    run_research(self, project, scan_id, manifest, cancel, progress)
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
                    "UPDATE scanner_runs SET status=?,finished=? WHERE scan_id=? AND status IN ('pending','running')",
                    ("cancelled" if status == "cancelled" else "interrupted", now(), scan_id),
                )
                self.db.execute(
                    "UPDATE scans SET status=?,finished=?,errors=?,duration=? WHERE id=?",
                    (status, now(), json.dumps(errors), time.monotonic() - started, scan_id),
                )
                self.db.audit("scan.finish", {"id": scan_id, "status": status, "errors": errors})
            return scan_id

    def investigate(self, finding_id: int) -> dict:
        record = self.db.finding(finding_id)
        finding: Finding = record["finding"]
        snapshot = self.managed_snapshot(finding.evidence["snapshot"])
        path = confined(snapshot, finding.path)
        with path.open("rb") as source:
            content = source.read(self.limits.max_file_bytes + 1)
        if len(content) > self.limits.max_file_bytes:
            raise OberhauError("Investigation source exceeds configured size limit")
        unchanged = hashlib.sha256(content).hexdigest() == finding.evidence.get("source_sha256")
        lines = source_lines(content.decode("utf-8", errors="replace"), path.suffix == ".py")
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
            "python_analysis": self.python_analysis(content, finding)
            if unchanged and path.suffix == ".py"
            else None,
            "contextual_hypothesis": finding.evidence.get("hypothesis"),
            "evidence_graph": self.research_graph(finding.evidence.get("research_run")),
        }

    def research_graph(self, run_id: int | None) -> dict | None:
        if run_id is None:
            return None
        rows = self.db.query(
            "SELECT data FROM research_runs WHERE id=? AND status='completed'", (run_id,)
        )
        return json.loads(rows[0]["data"]).get("graph") if rows else None

    @staticmethod
    def python_analysis(content: bytes, finding: Finding) -> dict:
        from oberhau.python_analysis import source_trace

        return source_trace(content.decode("utf-8", errors="replace"), finding.line, finding.rule)
