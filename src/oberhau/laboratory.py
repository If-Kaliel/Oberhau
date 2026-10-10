from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from oberhau.core import OberhauError, Status, now
from oberhau.database import Database
from oberhau.engine import ASSETS
from oberhau.security import confined


def validate_sql(db: Database, finding_id: int) -> dict:
    """Replay one bundled SQL fixture with trusted code, never import/exec target source."""
    record = db.finding(finding_id)
    finding = record["finding"]
    if finding.scanner != "builtin" or finding.rule != "python-sql-format":
        raise OberhauError("Only the bundled SQL fixture has automated behavioral validation")
    projects = db.query("SELECT * FROM projects WHERE id=?", (record["project_id"],))
    source = confined(Path(projects[0]["root"]), finding.path)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    expected = hashlib.sha256((ASSETS / "demo/vulnerable.py").read_bytes()).hexdigest()
    if (
        not projects[0]["demo"]
        or digest != expected
        or digest != finding.evidence.get("source_sha256")
    ):
        raise OberhauError(
            "Validation restricted to the unchanged, explicitly labeled bundled demonstration fixture"
        )
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(
            "CREATE TABLE users(name TEXT); INSERT INTO users VALUES('alice'),('bob');"
        )
        supplied = "' OR '1'='1"
        observed = connection.execute(
            f"SELECT name FROM users WHERE name = '{supplied}'"
        ).fetchall()
        corrected = connection.execute(
            "SELECT name FROM users WHERE name = ?", (supplied,)
        ).fetchall()
    result = {
        "passed": len(observed) == 2 and len(corrected) == 0,
        "fixture": "bundled SQL lookup only",
        "source_sha256": digest,
        "environment": "isolated SQLite :memory:",
        "input": supplied,
        "expected_rows": 0,
        "observed_rows": len(observed),
        "fixed_rows": len(corrected),
        "limitations": "Trusted reproduction of the checksum-matched bundled fixture. No claims about other applications.",
        "created": now(),
    }
    db.execute(
        "INSERT INTO validations(finding_id,result,created) VALUES(?,?,?)",
        (finding_id, json.dumps(result), now()),
    )
    if result["passed"]:
        db.review(
            finding_id,
            Status.REPRODUCED,
            "Bundled fixture reproduced in disposable SQLite; corrected control passed.",
        )
    db.audit("laboratory.validate", {"finding": finding_id, **result})
    return result
