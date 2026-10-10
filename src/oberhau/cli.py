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
    commands.add_parser(
        "benchmark", help="Evaluate trusted synthetic positive/negative cases independently"
    )
    queue = commands.add_parser(
        "research-queue", help="Prioritized evidence-based queue; retains human decisions"
    )
    queue.add_argument("--project", type=int)
    research = commands.add_parser(
        "research-details", help="Stored graph, contextual hypotheses, coverage and changes"
    )
    research.add_argument("run", type=int)
    assistant = commands.add_parser(
        "research-assist", help="Bounded local Qwen evidence queries; deterministic fallback"
    )
    assistant.add_argument("run", type=int)
    assistant.add_argument("--ai", action="store_true")
    runs = commands.add_parser(
        "scanner-runs", help="Per-scanner status, timing, counts and provenance"
    )
    runs.add_argument("--scan", type=int)
    commands.add_parser("demo")
    commands.add_parser(
        "demo-multilang", help="Import static web/Java/.NET controls and run Semgrep"
    )
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
    git_add = commands.add_parser(
        "add-git", help="Import a public HTTPS repository as a verified committed snapshot"
    )
    git_add.add_argument("url")
    git_add.add_argument("--name", required=True)
    git_add.add_argument("--ref")
    git_add.add_argument("--program", type=int)
    git_link = commands.add_parser("relink-git")
    git_link.add_argument("project", type=int)
    git_link.add_argument("url")
    git_link.add_argument("--ref")
    compare = commands.add_parser(
        "compare", help="Redacted source diff against the previous snapshot"
    )
    compare.add_argument("project", type=int)
    compare.add_argument("path")
    details = commands.add_parser("project-details")
    details.add_argument("project", type=int)
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
    local_lab = commands.add_parser(
        "local-lab", help="Disposable trusted synthetic loopback HTTP regressions"
    )
    local_lab.add_argument("recipe", choices=["authorization", "input-validation"])
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
        elif args.command == "add-git":
            output = {
                "project": engine.repositories().add(
                    args.url,
                    args.name,
                    args.program,
                    args.ref,
                    cancel,
                    lambda message: print(message, file=sys.stderr),
                )
            }
        elif args.command == "relink-git":
            engine.repositories().relink(args.project, args.url, args.ref)
            output = {"relinked": args.project, "source": args.url}
        elif args.command == "compare":
            output = engine.compare_source(args.project, args.path)
        elif args.command == "project-details":
            output = engine.ingestion.project(args.project)
            output["metadata"] = json.loads(output["metadata"])
        elif args.command == "demo":
            project = engine.ingestion.add(ASSETS / "demo", "DEMONSTRATION / LABORATORY", demo=True)
            output = {"project": project, "scan": engine.scan(project, "quick", cancel)}
        elif args.command == "demo-multilang":
            project = engine.ingestion.add(
                ASSETS / "multilang", "DEMONSTRATION / MULTILANGUAGE", demo=True
            )
            output = {"project": project, "scan": engine.scan(project, "standard", cancel)}
        elif args.command == "projects":
            output = db.query("SELECT id,name,origin,demo,created FROM projects")
        elif args.command == "metrics":
            output = db.metrics()
        elif args.command == "benchmark":
            from oberhau.benchmark import evaluate

            output = evaluate(cancel)
            db.set_setting("last_research_benchmark", output)
        elif args.command == "research-queue":
            from oberhau.research import research_queue

            output = research_queue(db, args.project)
        elif args.command == "research-details":
            from oberhau.research_assistant import ResearchTools

            output = ResearchTools(engine, args.run).data
        elif args.command == "research-assist":
            from oberhau.research_assistant import assist

            output = assist(engine, args.run, args.ai, cancel)
        elif args.command == "scanner-runs":
            output = db.scanner_runs(args.scan)
        elif args.command == "refresh":
            engine.refresh_project(
                args.project, cancel, lambda message: print(message, file=sys.stderr)
            )
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
        elif args.command == "local-lab":
            from oberhau.local_validation import validate_local

            output = validate_local(db, args.recipe, cancel)
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
