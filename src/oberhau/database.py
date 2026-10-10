from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from oberhau.core import Finding, OberhauError, Status, now
from oberhau.correlation import advisory_aliases, dependency_scope
from oberhau.security import redact, sanitize

MIGRATIONS = [
    """
    CREATE TABLE programs(id INTEGER PRIMARY KEY, name TEXT NOT NULL, policy_url TEXT NOT NULL,
        policy TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '', updated TEXT NOT NULL);
    CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL, root TEXT UNIQUE NOT NULL,
        origin TEXT NOT NULL, program_id INTEGER REFERENCES programs(id),
        metadata TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
    CREATE TABLE scans(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
        profile TEXT NOT NULL, status TEXT NOT NULL, started TEXT NOT NULL, finished TEXT,
        commit_hash TEXT, file_count INTEGER NOT NULL DEFAULT 0, manifest TEXT NOT NULL DEFAULT '{}',
        errors TEXT NOT NULL DEFAULT '[]', duration REAL NOT NULL DEFAULT 0);
    CREATE TABLE findings(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
        fingerprint TEXT UNIQUE NOT NULL, data TEXT NOT NULL, status TEXT NOT NULL,
        first_scan INTEGER NOT NULL REFERENCES scans(id), last_scan INTEGER NOT NULL REFERENCES scans(id),
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1,
        notes TEXT NOT NULL DEFAULT '');
    CREATE TABLE observations(id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
        scan_id INTEGER NOT NULL REFERENCES scans(id), data TEXT NOT NULL,
        UNIQUE(finding_id, scan_id));
    CREATE TABLE reports(id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
        content TEXT NOT NULL, language TEXT NOT NULL, generator TEXT NOT NULL, created TEXT NOT NULL);
    CREATE TABLE validations(id INTEGER PRIMARY KEY, finding_id INTEGER REFERENCES findings(id),
        result TEXT NOT NULL, created TEXT NOT NULL);
    CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE audit(id INTEGER PRIMARY KEY, event TEXT NOT NULL, details TEXT NOT NULL, created TEXT NOT NULL);
    CREATE TABLE schedules(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
        profile TEXT NOT NULL, interval_minutes INTEGER NOT NULL CHECK(interval_minutes >= 1),
        enabled INTEGER NOT NULL DEFAULT 1, next_run TEXT NOT NULL);
    CREATE TABLE rewards(id INTEGER PRIMARY KEY, finding_id INTEGER REFERENCES findings(id),
        amount REAL NOT NULL CHECK(amount >= 0), hours REAL NOT NULL CHECK(hours >= 0),
        outcome TEXT NOT NULL, created TEXT NOT NULL);
    """,
    """
    ALTER TABLE observations RENAME TO observations_v1;
    CREATE TABLE observations(id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
        scan_id INTEGER NOT NULL REFERENCES scans(id), scanner TEXT NOT NULL, data TEXT NOT NULL,
        UNIQUE(finding_id, scan_id, scanner));
    INSERT INTO observations(id,finding_id,scan_id,scanner,data)
        SELECT id,finding_id,scan_id,json_extract(data,'$.scanner'),data FROM observations_v1;
    DROP TABLE observations_v1;
    """,
    """
    ALTER TABLE observations RENAME TO observations_v2;
    CREATE TABLE observations(id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
        scan_id INTEGER NOT NULL REFERENCES scans(id), scanner TEXT NOT NULL, rule TEXT NOT NULL,
        data TEXT NOT NULL, UNIQUE(finding_id,scan_id,scanner,rule));
    INSERT INTO observations(id,finding_id,scan_id,scanner,rule,data)
        SELECT id,finding_id,scan_id,scanner,json_extract(data,'$.rule'),data FROM observations_v2;
    DROP TABLE observations_v2;
    CREATE TABLE scanner_runs(id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id),
        scanner TEXT NOT NULL, status TEXT NOT NULL, started TEXT, finished TEXT,
        duration REAL NOT NULL DEFAULT 0, findings INTEGER NOT NULL DEFAULT 0,
        errors TEXT NOT NULL DEFAULT '[]', provenance TEXT NOT NULL DEFAULT '{}',
        UNIQUE(scan_id,scanner));
    CREATE INDEX scanner_runs_scan ON scanner_runs(scan_id);
    CREATE TABLE advisory_links(project_id INTEGER NOT NULL REFERENCES projects(id),
        scope TEXT NOT NULL, advisory TEXT NOT NULL, finding_id INTEGER NOT NULL REFERENCES findings(id),
        PRIMARY KEY(project_id,scope,advisory));
    CREATE INDEX advisory_links_finding ON advisory_links(finding_id);
    """,
    """
    CREATE TABLE research_runs(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
        scan_id INTEGER NOT NULL REFERENCES scans(id), status TEXT NOT NULL, started TEXT NOT NULL,
        finished TEXT, commit_hash TEXT, manifest TEXT NOT NULL DEFAULT '{}',
        data TEXT NOT NULL DEFAULT '{}', errors TEXT NOT NULL DEFAULT '[]', duration REAL NOT NULL DEFAULT 0);
    CREATE INDEX research_runs_project ON research_runs(project_id,id);
    CREATE TABLE research_files(project_id INTEGER NOT NULL REFERENCES projects(id),
        path TEXT NOT NULL, sha256 TEXT NOT NULL, version TEXT NOT NULL, data TEXT NOT NULL,
        PRIMARY KEY(project_id,path,sha256,version));
    CREATE TABLE research_assistance(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES research_runs(id),
        status TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL);
    """,
]


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > len(MIGRATIONS):
                raise OberhauError("Database was created by a newer Oberhau version")
            for index in range(version, len(MIGRATIONS)):
                try:
                    connection.executescript(
                        f"BEGIN IMMEDIATE;\n{MIGRATIONS[index]}\nPRAGMA user_version={index + 1};\nCOMMIT;"
                    )
                except sqlite3.Error as error:
                    connection.rollback()
                    raise OberhauError(f"Database migration {index + 1} failed: {error}") from error
            indexed = connection.execute(
                "SELECT value FROM settings WHERE key='advisory_index_version'"
            ).fetchone()
            if indexed is None or indexed[0] != "1":
                for row in connection.execute(
                    "SELECT id,project_id,data FROM findings UNION ALL SELECT f.id,f.project_id,o.data FROM observations o JOIN findings f ON f.id=o.finding_id ORDER BY id"
                ):
                    finding = Finding.model_validate_json(row["data"])
                    scope = dependency_scope(finding)
                    if scope:
                        self.link_advisories(
                            connection, row["project_id"], scope, row["id"], finding
                        )
                connection.execute(
                    "INSERT OR REPLACE INTO settings VALUES('advisory_index_version','1')"
                )
            # Interrupted jobs remain visible and cannot masquerade as completed.
        self.audit("database.open", {"schema": len(MIGRATIONS)})

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def query(self, sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, args)]

    def execute(self, sql: str, args: tuple[Any, ...] = ()) -> int:
        with self.connect() as connection:
            cursor = connection.execute(sql, args)
            return int(cursor.lastrowid or 0)

    def audit(self, event: str, details: Any) -> None:
        self.execute(
            "INSERT INTO audit(event,details,created) VALUES(?,?,?)",
            (event, json.dumps(sanitize(details), ensure_ascii=False), now()),
        )

    def setting(self, key: str, default: Any = None) -> Any:
        rows = self.query("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )

    def save_finding(
        self,
        project_id: int,
        scan_id: int,
        finding: Finding,
        connection: sqlite3.Connection | None = None,
    ) -> int:
        finding = Finding.model_validate(sanitize(finding.model_dump()))
        observation_data = finding.model_dump_json()
        fingerprint = finding.fingerprint(project_id)
        scope = dependency_scope(finding)
        with nullcontext(connection) if connection is not None else self.connect() as connection:
            aliases = advisory_aliases(finding) if scope else set()
            related = set()
            for alias in aliases:
                row = connection.execute(
                    "SELECT finding_id FROM advisory_links WHERE project_id=? AND scope=? AND advisory=?",
                    (project_id, scope, alias),
                ).fetchone()
                if row:
                    related.add(row[0])
            existing = connection.execute(
                "SELECT id,status,last_scan,data FROM findings WHERE "
                + ("id=?" if related else "fingerprint=?"),
                (min(related) if related else fingerprint,),
            ).fetchone()
            if existing:
                finding_id = existing["id"]
                state = (
                    Status.SUSPECTED if existing["status"] == Status.FIXED else existing["status"]
                )
                old = Finding.model_validate_json(existing["data"])
                if scope and dependency_scope(old) == scope:
                    finding.advisories = sorted(set(old.advisories) | set(finding.advisories))
                    finding.evidence["correlation"] = {
                        "basis": "Same manifest, package/version and explicit advisory alias",
                        "related_historical_ids": sorted(related - {finding_id}),
                    }
                    rank = {"informative": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                    if rank.get(old.severity, 2) > rank.get(finding.severity, 2):
                        finding.severity = old.severity
                old_references = {
                    (ref.get("path"), ref.get("sha256"))
                    for ref in old.evidence.get("references", [])
                }
                new_references = {
                    (ref.get("path"), ref.get("sha256"))
                    for ref in finding.evidence.get("references", [])
                }
                evidence_changed = (
                    old.evidence.get("source_sha256") != finding.evidence.get("source_sha256")
                    or old_references != new_references
                )
                if evidence_changed and existing["status"] in {
                    Status.VERIFIED,
                    Status.READY,
                    Status.FALSE_POSITIVE,
                    Status.REPRODUCED,
                }:
                    state = Status.SUSPECTED
                connection.execute(
                    "UPDATE findings SET data=?,last_scan=?,last_seen=?,occurrences=occurrences+?,status=? WHERE id=?",
                    (
                        finding.model_dump_json(),
                        scan_id,
                        now(),
                        int(existing["last_scan"] != scan_id),
                        state,
                        finding_id,
                    ),
                )
            else:
                cursor = connection.execute(
                    "INSERT INTO findings(project_id,fingerprint,data,status,first_scan,last_scan,first_seen,last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (
                        project_id,
                        fingerprint,
                        finding.model_dump_json(),
                        finding.status,
                        scan_id,
                        scan_id,
                        now(),
                        now(),
                    ),
                )
                finding_id = cursor.lastrowid
            connection.execute(
                "INSERT OR IGNORE INTO observations(finding_id,scan_id,scanner,rule,data) VALUES(?,?,?,?,?)",
                (finding_id, scan_id, finding.scanner, finding.rule, observation_data),
            )
            if scope:
                self.link_advisories(connection, project_id, scope, finding_id, finding)
            return int(finding_id)

    @staticmethod
    def link_advisories(
        connection: sqlite3.Connection,
        project_id: int,
        scope: str,
        finding_id: int,
        finding: Finding,
    ) -> None:
        for alias in advisory_aliases(finding):
            connection.execute(
                "INSERT OR IGNORE INTO advisory_links VALUES(?,?,?,?)",
                (project_id, scope, alias, finding_id),
            )

    def scanner_runs(self, scan_id: int | None = None) -> list[dict]:
        return self.query(
            "SELECT r.*,s.project_id,s.profile FROM scanner_runs r JOIN scans s ON s.id=r.scan_id"
            + (" WHERE scan_id=?" if scan_id is not None else "")
            + " ORDER BY r.id DESC LIMIT 500",
            (scan_id,) if scan_id is not None else (),
        )

    def finding(self, finding_id: int) -> dict[str, Any]:
        rows = self.query("SELECT * FROM findings WHERE id=?", (finding_id,))
        if not rows:
            raise OberhauError("Finding does not exist")
        record = rows[0]
        record["finding"] = Finding.model_validate_json(record["data"])
        return record

    def review(self, finding_id: int, status: Status, notes: str) -> None:
        self.finding(finding_id)
        if status == Status.REPRODUCED:
            results = self.query("SELECT result FROM validations WHERE finding_id=?", (finding_id,))
            if not any(json.loads(r["result"]).get("passed") for r in results):
                raise OberhauError("Local reproduction requires a passing laboratory record")
        if status in {Status.VERIFIED, Status.READY, Status.FALSE_POSITIVE} and not notes.strip():
            raise OberhauError("This decision requires human evidence or rationale in notes")
        self.execute(
            "UPDATE findings SET status=?,notes=? WHERE id=?", (status, redact(notes), finding_id)
        )
        self.audit("finding.review", {"id": finding_id, "status": status, "notes": notes})

    def backup(self, destination: Path) -> None:
        if destination.resolve() == self.path.resolve() or destination.exists():
            raise OberhauError("Backup destination must be a new file")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as source, sqlite3.connect(destination) as target:
            source.backup(target)
        self.audit("database.backup", {"destination": str(destination)})

    @staticmethod
    def restore(source: Path, destination: Path) -> None:
        from oberhau.backup import upgrade_database, validate_database

        if destination.exists():
            raise OberhauError(
                "Restore into a new database file; do not overwrite an open database"
            )
        connection = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
        try:
            version = validate_database(connection)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(destination) as target:
                connection.backup(target)
                upgrade_database(target, version)
        finally:
            connection.close()

    def metrics(self) -> dict[str, Any]:
        return {
            "projects": self.query("SELECT count(*) AS n FROM projects")[0]["n"],
            "scans": self.query("SELECT count(*) AS n FROM scans")[0]["n"],
            "files": self.query("SELECT coalesce(sum(file_count),0) AS n FROM scans")[0]["n"],
            "reports": self.query("SELECT count(*) AS n FROM reports")[0]["n"],
            "findings": self.query("SELECT status,count(*) AS n FROM findings GROUP BY status"),
            "rewards": self.query(
                "SELECT coalesce(sum(amount),0) AS amount,coalesce(sum(hours),0) AS hours FROM rewards"
            )[0],
            "scanners": self.query(
                "SELECT o.scanner,count(DISTINCT o.finding_id) AS findings,count(*) AS observations,"
                "count(DISTINCT CASE WHEN f.status='False Positive' THEN f.id END) AS false_positives,"
                "count(DISTINCT CASE WHEN f.status IN ('Human Verified','Report Ready','Accepted') THEN f.id END) AS verified "
                "FROM observations o JOIN findings f ON f.id=o.finding_id GROUP BY o.scanner"
            ),
            "severity": self.query(
                "SELECT json_extract(data,'$.severity') AS severity,count(*) AS n FROM findings GROUP BY severity"
            ),
            "confidence": self.query(
                "SELECT CASE WHEN json_extract(data,'$.confidence')>=0.8 THEN 'high' "
                "WHEN json_extract(data,'$.confidence')>=0.5 THEN 'medium' ELSE 'low' END AS confidence,"
                "count(*) AS n FROM findings GROUP BY confidence"
            ),
            "manual_outcomes": self.query(
                "SELECT outcome,count(*) AS n FROM rewards GROUP BY outcome"
            ),
            "scan_seconds": self.query("SELECT coalesce(sum(duration),0) AS n FROM scans")[0]["n"],
        }
