"""Bound research storage without discarding evidence or human review history."""

from __future__ import annotations

import json
from threading import Event

from pydantic import BaseModel, ConfigDict, Field

from oberhau.core import Cancelled, OberhauError
from oberhau.storage import store_lock


class RetentionLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cache_bytes: int = Field(default=64_000_000, ge=1000, le=1_000_000_000)
    history_bytes: int = Field(default=256_000_000, ge=1000, le=2_000_000_000)
    runs_per_project: int = Field(default=500, ge=1, le=10000)


def usage(db) -> dict:
    def size(table, expression):
        return db.query(f"SELECT COALESCE(SUM({expression}),0) AS bytes FROM {table}")[0]["bytes"]

    return {
        "cache_bytes": size("research_files", "length(CAST(data AS BLOB))"),
        "history_bytes": size(
            "research_runs", "length(CAST(data AS BLOB))+length(CAST(manifest AS BLOB))"
        )
        + size("research_assistance", "length(CAST(data AS BLOB))"),
        "cache_records": db.query("SELECT COUNT(*) AS n FROM research_files")[0]["n"],
        "runs": db.query("SELECT COUNT(*) AS n FROM research_runs")[0]["n"],
        "limits": RetentionLimits.model_validate(db.setting("retention_limits", {})).model_dump(),
        "scope": "Logical research JSON bytes, not an OS disk quota. Snapshots, scanner history, reports and human decisions are preserved.",
    }


def reserve(db, *, cache=0, history=0, project=None, current=None):
    current = usage(db) if current is None else current
    limits = current["limits"]
    if current["cache_bytes"] + cache > limits["cache_bytes"]:
        raise OberhauError(
            "Research cache budget exceeded; preview cache maintenance or raise the limit"
        )
    if current["history_bytes"] + history > limits["history_bytes"]:
        raise OberhauError(
            "Research history budget exceeded; export a complete backup and choose a new data directory, or raise the limit"
        )
    if project is not None:
        count = db.query("SELECT COUNT(*) AS n FROM research_runs WHERE project_id=?", (project,))[
            0
        ]["n"]
        if count >= limits["runs_per_project"]:
            raise OberhauError(
                "Research run retention limit reached; back up history and choose a new data directory, or raise the limit"
            )
    current["cache_bytes"] += cache
    current["history_bytes"] += history
    return current


def maintain(engine, apply=False, cancel: Event | None = None) -> dict:
    """Remove only summaries not needed by any completed historical run."""
    cancel = cancel or Event()
    with store_lock(engine.home):
        pinned = set()
        for row in engine.db.query(
            "SELECT project_id,manifest,data FROM research_runs WHERE status='completed'"
        ):
            if cancel.is_set():
                raise Cancelled()
            data = json.loads(row["data"])
            version = data.get("index", {}).get("version")
            for path, digest in json.loads(row["manifest"]).items():
                pinned.add((row["project_id"], path, digest, version))
        candidates = []
        for row in engine.db.query(
            "SELECT project_id,path,sha256,version,length(CAST(data AS BLOB)) AS bytes FROM research_files"
        ):
            if cancel.is_set():
                raise Cancelled()
            key = tuple(row[k] for k in ("project_id", "path", "sha256", "version"))
            # Older runs without recorded parser version protect all versions of their source.
            if key not in pinned and (*key[:3], None) not in pinned:
                candidates.append(row)
        before = usage(engine.db)
        if apply:
            with engine.db.connect() as connection:
                for row in candidates:
                    if cancel.is_set():
                        raise Cancelled()
                    connection.execute(
                        "DELETE FROM research_files WHERE project_id=? AND path=? AND sha256=? AND version=?",
                        tuple(row[k] for k in ("project_id", "path", "sha256", "version")),
                    )
            engine.db.audit(
                "research.cache-maintenance",
                {"records": len(candidates), "bytes": sum(r["bytes"] for r in candidates)},
            )
        return {
            "applied": apply,
            "eligible_records": len(candidates),
            "eligible_bytes": sum(r["bytes"] for r in candidates),
            "before": before,
            "after": usage(engine.db),
            "preserved": "All completed research runs, source snapshots, findings, observations, reports and human decisions",
        }
