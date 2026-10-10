from __future__ import annotations

import argparse
import json
import signal
import sqlite3
import sys
from pathlib import Path
from threading import Event

from oberhau.backup import create_backup, restore_backup
from oberhau.core import Cancelled, OberhauError, Status, data_home
from oberhau.database import Database
from oberhau.diagnostics import collect
from oberhau.engine import ASSETS, PROFILES, Engine
from oberhau.laboratory import validate_sql
from oberhau.reporting import export, generate
from oberhau.scheduler import add_schedule
from oberhau.tooling import ECOSYSTEMS, PINNED, install_tool, refresh_osv_cache, refresh_trivy_cache


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
    commands.add_parser(
        "refresh-trivy-cache", help="Download the public Trivy vulnerability database"
    )
    install = commands.add_parser(
        "install-tool", help="Download a pinned official Windows x64 scanner"
    )
    install.add_argument("tool", choices=PINNED)
    cache = commands.add_parser(
        "refresh-osv-cache", help="Download a public advisory feed; no project data is sent"
    )
    cache.add_argument("ecosystem", choices=ECOSYSTEMS)
    add = commands.add_parser("add")
    add.add_argument("source", type=Path)
    add.add_argument("--name", required=True)
    add.add_argument("--program", type=int)
    scan = commands.add_parser("scan")
    scan.add_argument("project", type=int)
    scan.add_argument("--profile", choices=PROFILES, default="standard")
    refresh = commands.add_parser("refresh")
    refresh.add_argument("project", type=int)
    relink = commands.add_parser(
        "relink", help="Explicitly link a project's original source on this computer"
    )
    relink.add_argument("project", type=int)
    relink.add_argument("source", type=Path)
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
    backup.add_argument(
        "--complete",
        action="store_true",
        help="Include all retained source snapshots in a portable ZIP",
    )
    restore = commands.add_parser("restore")
    restore.add_argument("source", type=Path)
    restore.add_argument("destination", type=Path)
    restore.add_argument(
        "--complete",
        action="store_true",
        help="Restore a portable research ZIP into a new data directory",
    )
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
        if args.command == "restore":
            if args.complete:
                output = restore_backup(
                    args.source,
                    args.destination,
                    cancel,
                    lambda message: print(message, file=sys.stderr),
                )
            else:
                Database.restore(args.source, args.destination)
                output = {"restored": str(args.destination)}
            print(json.dumps(output, indent=2, ensure_ascii=False))
            return 0
        engine = Engine(args.home)
        db = engine.db
        output = None
        if args.command == "diagnostics":
            output = collect(home=engine.home)
        elif args.command == "install-tool":
            output = install_tool(engine.home, args.tool, cancel, print)
        elif args.command == "refresh-osv-cache":
            output = refresh_osv_cache(engine.home, args.ecosystem, cancel, print)
        elif args.command == "refresh-trivy-cache":
            output = refresh_trivy_cache(engine.home, cancel, print)
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
        elif args.command == "relink":
            engine.ingestion.relink(args.project, args.source)
            output = {"relinked": args.project, "source": str(args.source)}
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
            if args.complete:
                output = create_backup(
                    db,
                    engine.home,
                    args.destination,
                    cancel,
                    lambda message: print(message, file=sys.stderr),
                )
            else:
                db.backup(args.destination)
                output = {"backup": str(args.destination)}
        elif args.command == "schedule":
            output = {
                "schedule": add_schedule(db, args.project, args.profile, args.minutes),
                "execution": "Only while the GUI is open and idle; no Windows startup service",
            }
        print(json.dumps(output, indent=2, ensure_ascii=False, default=str))
        return 0
    except Cancelled:
        print("Oberhau operation cancelled")
        return 130
    except (OberhauError, OSError, ValueError, sqlite3.Error) as error:
        print(f"Oberhau error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
