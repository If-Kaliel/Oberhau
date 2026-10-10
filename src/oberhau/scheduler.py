from __future__ import annotations

from datetime import UTC, datetime, timedelta

from oberhau.core import OberhauError, now
from oberhau.database import Database
from oberhau.engine import PROFILES


def add_schedule(db: Database, project_id: int, profile: str, minutes: int) -> int:
    if profile not in PROFILES or not 1 <= minutes <= 525600:
        raise OberhauError("Invalid offline profile or schedule interval")
    return db.execute(
        "INSERT INTO schedules(project_id,profile,interval_minutes,next_run) VALUES(?,?,?,?)",
        (project_id, profile, minutes, now()),
    )


def take_due(db: Database) -> dict | None:
    # Transactional claim prevents two in-app workers from taking the same due interval.
    with db.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run<=? ORDER BY next_run LIMIT 1",
            (now(),),
        ).fetchone()
        if row is None:
            return None
        next_run = (datetime.now(UTC) + timedelta(minutes=row["interval_minutes"])).isoformat()
        connection.execute("UPDATE schedules SET next_run=? WHERE id=?", (next_run, row["id"]))
        return dict(row)
