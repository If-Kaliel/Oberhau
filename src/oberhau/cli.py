from __future__ import annotations

import argparse
import json
import signal
from pathlib import Path
from threading import Event

from oberhau.core import OberhauError, Status, data_home
from oberhau.database import Database
from oberhau.diagnostics import collect
from oberhau.engine import ASSETS, PROFILES, Engine
from oberhau.laboratory import validate_sql
from oberhau.reporting import export, generate
from oberhau.scheduler import add_schedule


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="oberhau", description="Offline Security Research Workbench"
    )
    parser.add_argument("--home", type=Path, default=data_home(), help="Local data directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("gui")
    commands.add_parser("diagnostics")
    commands.add_parser("projects")
    commands.add_parser("metrics")
    commands.add_parser("demo")
    add = commands.add_parser("add")
    add.add_argument("source", type=Path)
    add.add_argument("--name", required=True)
    add.add_argument("--program", type=int)
    scan = commands.add_parser("scan")
    scan.add_argument("project", type=int)
    scan.add_argument("--profile", choices=PROFILES, default="standard")
    refresh = commands.add_parser("refresh")
    refresh.add_argument("project", type=int)
    findings = commands.add_parser("findings")
    findings.add_argument("--project", type=int)
    investigate = commands.add_parser("investigate")
    investigate.add_argument("finding", type=int)
    review = commands.add_parser("review")
    review.add_argument("finding", type=int)
    review.add_argument("--status", choices=list(Status), required=True)
    review.add_argument("--notes", default="")
    lab = commands.add_parser("validate")
    lab.add_argument("finding", type=int)
    report = commands.add_parser("report")
    report.add_argument("finding", type=int)
    report.add_argument("--language", choices=["en", "pt-BR"], default="en")
    report.add_argument("--ai", action="store_true")
    report.add_argument("--output", type=Path, required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("destination", type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("source", type=Path)
    restore.add_argument("destination", type=Path)
    schedule = commands.add_parser("schedule")
    schedule.add_argument("project", type=int)
    schedule.add_argument("--profile", choices=PROFILES, default="quick")
    schedule.add_argument("--minutes", type=int, default=60)
    args = parser.parse_args(argv)
    cancel = Event()
    signal.signal(signal.SIGINT, lambda *_: cancel.set())
    try:
        if args.command == "gui":
            from oberhau.desktop.app import main as desktop

            return desktop(args.home)
        engine = Engine(args.home)
        db = engine.db
        output = None
        if args.command == "diagnostics":
            output = collect()
        elif args.command == "add":
            output = {"project": engine.ingestion.add(args.source, args.name, args.program)}
        elif args.command == "demo":
            project = engine.ingestion.add(ASSETS / "demo", "DEMONSTRATION / LABORATORY", demo=True)
            output = {"project": project, "scan": engine.scan(project, "quick", cancel)}
        elif args.command == "projects":
            output = db.query("SELECT id,name,origin,demo,created FROM projects")
        elif args.command == "metrics":
            output = db.metrics()
        elif args.command == "refresh":
            engine.ingestion.refresh(args.project)
            output = {"refreshed": args.project}
        elif args.command == "scan":
            scan_id = engine.scan(
                args.project, args.profile, cancel, lambda message: print(message)
            )
            output = db.query("SELECT * FROM scans WHERE id=?", (scan_id,))[0]
            print(json.dumps(output, indent=2, ensure_ascii=False))
            return 0 if output["status"] == "completed" else 2
        elif args.command == "findings":
            output = db.query(
                "SELECT id,project_id,data,status,occurrences FROM findings"
                + (" WHERE project_id=?" if args.project else ""),
                (args.project,) if args.project else (),
            )
        elif args.command == "investigate":
            output = engine.investigate(args.finding)
        elif args.command == "review":
            db.review(args.finding, Status(args.status), args.notes)
            output = {"reviewed": args.finding, "status": args.status}
        elif args.command == "validate":
            output = validate_sql(db, args.finding)
        elif args.command == "report":
            report_id, _ = generate(db, args.finding, args.language, args.ai, cancel)
            export(db, report_id, args.output)
            output = {"report": report_id, "output": str(args.output)}
        elif args.command == "backup":
            db.backup(args.destination)
            output = {"backup": str(args.destination)}
        elif args.command == "restore":
            Database.restore(args.source, args.destination)
            output = {"restored": str(args.destination)}
        elif args.command == "schedule":
            output = {
                "schedule": add_schedule(db, args.project, args.profile, args.minutes),
                "execution": "Only while the GUI is open and idle; no Windows startup service",
            }
        print(json.dumps(output, indent=2, ensure_ascii=False, default=str))
        return 0
    except (OberhauError, OSError, ValueError) as error:
        print(f"Oberhau error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
