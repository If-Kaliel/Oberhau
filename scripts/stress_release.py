"""Reproducible large-project, repeated-run, cancellation and process-loss QA."""

import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oberhau.engine import Engine  # noqa: E402
from oberhau.maintenance import maintain, usage  # noqa: E402
from oberhau.resources import process_memory  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child-home", type=Path)
    parser.add_argument("--project", type=int)
    args = parser.parse_args()
    if args.child_home:
        engine = Engine(args.child_home)
        count = 0

        def blocked(message):
            nonlocal count
            if message.startswith("Contextual indexing:"):
                count += 1
                if count == 50:
                    print("READY_FOR_OWNED_TERMINATION", flush=True)
                    threading.Event().wait(120)

        engine.scan(args.project, "research", progress=blocked)
        return
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="release-stress-", dir=ROOT / ".oberhau") as directory:
        directory = Path(directory)
        source = directory / "source"
        source.mkdir()
        for index in range(1500):
            (source / f"helper{index:04}.ts").write_text(
                f"export function helper{index}(value:string) {{ const copy=value; return copy; }}"
            )
        (source / "route.ts").write_text(
            "export function GET(req:Request, params:any) { return db.user.findUnique({where:{id:params.id}}); }"
        )
        engine = Engine(directory / "home")
        project = engine.ingestion.add(source, "DEMONSTRATION / 1501-file stress corpus", demo=True)
        measurements = []
        for i in range(10):
            begin = time.monotonic()
            scan = engine.scan(project, "research")
            row = engine.db.query("SELECT * FROM research_runs WHERE scan_id=?", (scan,))[0]
            data = json.loads(row["data"])
            assert row["status"] == "completed" and len(data["hypotheses"]) == 1
            assert data["index"]["parsed"] == (1501 if i == 0 else 0)
            assert data["index"]["reused"] == (0 if i == 0 else 1501)
            measurements.append(
                {
                    "iteration": i + 1,
                    "seconds": time.monotonic() - begin,
                    "index": data["index"],
                    "nodes": len(data["graph"]["nodes"]),
                    "memory": process_memory(),
                }
            )
        cancelled_project = engine.ingestion.add(
            source, "DEMONSTRATION / cancelled indexing", demo=True
        )
        cancel = threading.Event()

        def cancelling(message):
            if message.startswith("Contextual indexing: helper0049"):
                cancel.set()

        scan = engine.scan(cancelled_project, "research", cancel, cancelling)
        assert (
            engine.db.query("SELECT status FROM scans WHERE id=?", (scan,))[0]["status"]
            == "cancelled"
        )
        assert not engine.db.query(
            "SELECT id FROM findings WHERE project_id=?", (cancelled_project,)
        )
        cached_after_cancel = engine.db.query(
            "SELECT COUNT(*) AS n FROM research_files WHERE project_id=?", (cancelled_project,)
        )[0]["n"]
        scan = engine.scan(cancelled_project, "research")
        resumed = json.loads(
            engine.db.query("SELECT data FROM research_runs WHERE scan_id=?", (scan,))[0]["data"]
        )
        assert resumed["index"]["reused"] == cached_after_cancel
        lost = engine.ingestion.add(source, "DEMONSTRATION / actual process loss", demo=True)
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        child = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child-home",
                str(engine.home),
                "--project",
                str(lost),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        messages = queue.Queue()

        def reader():
            for line in child.stdout:
                messages.put(line.strip())

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            assert messages.get(timeout=60) == "READY_FOR_OWNED_TERMINATION"
        finally:
            child.terminate()
            child.wait(timeout=10)
            thread.join(timeout=2)
            child.stdout.close()
            child.stderr.close()
        engine = Engine(engine.home)
        recovered = engine.db.query(
            "SELECT status FROM research_runs WHERE project_id=? ORDER BY id DESC LIMIT 1", (lost,)
        )[0]["status"]
        assert recovered == "interrupted"
        scan = engine.scan(lost, "research")
        recovered_data = json.loads(
            engine.db.query("SELECT data FROM research_runs WHERE scan_id=?", (scan,))[0]["data"]
        )
        assert recovered_data["index"]["reused"] == 49
        preview = maintain(engine)
        result = {
            "seconds": time.monotonic() - started,
            "source_files": 1501,
            "completed_iterations": measurements,
            "cancellation": {
                "cached_files": cached_after_cancel,
                "resumed_index": resumed["index"],
                "partial_findings": 0,
            },
            "process_loss": {"startup_status": recovered, "resumed_index": recovered_data["index"]},
            "storage": usage(engine.db),
            "maintenance_preview": preview["eligible_records"],
            "limitations": "Owned synthetic stress corpus and same host. Not representative of every large repository, not an OS quota or a clean VM test. No imported code executed.",
        }
    target = ROOT / "artifacts/oberhau-1.0-stress.json"
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "report": str(target),
                "seconds": result["seconds"],
                "files": result["source_files"],
                "completed_runs": len(measurements),
                "recovered": recovered,
                "cancelled_cache_reused": cached_after_cancel,
            }
        )
    )


if __name__ == "__main__":
    main()
