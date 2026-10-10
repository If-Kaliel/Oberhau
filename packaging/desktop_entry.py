"""Native packaged entry, with an explicit isolated smoke mode for release QA."""

import argparse
import json
from pathlib import Path

from oberhau.core import data_home
from oberhau.frozen import prepare_runtime
from oberhau.parser_worker import dispatch


def main():
    parser = argparse.ArgumentParser(description="OBERHAU desktop")
    parser.add_argument("--home", type=Path, default=data_home())
    smoke = parser.add_mutually_exclusive_group()
    smoke.add_argument(
        "--smoke", type=Path, help="Run a labeled demo in --home and save a screenshot"
    )
    smoke.add_argument(
        "--smoke-research",
        type=Path,
        help="Run the bundled contextual fixture through the frozen GUI parser and capture Research",
    )
    args = parser.parse_args()
    capture_path = args.smoke or args.smoke_research
    if capture_path is None:
        from oberhau.desktop.app import main as desktop

        return desktop(args.home)
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from oberhau.desktop.app import PAGES, Window, configure_fonts
    from oberhau.desktop.theme import THEME
    from oberhau.engine import ASSETS, Engine

    engine = Engine(args.home)
    if args.smoke_research:
        from oberhau.security import confined

        case = json.loads((ASSETS / "research_benchmark.json").read_text())["cases"][3]
        source = confined(engine.home, "packaged-smoke-source")
        source.mkdir(exist_ok=True)
        for relative, code in case["sources"].items():
            path = confined(source, relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(code, encoding="utf-8")
        project = engine.ingestion.add(source, "DEMONSTRATION / PACKAGED RESEARCH QA", demo=True)
        engine.scan(project, "research")
    else:
        project = engine.ingestion.add(ASSETS / "demo", "DEMONSTRATION / PACKAGED QA", demo=True)
        engine.scan(project, "quick")
    app = QApplication([])
    configure_fonts()
    app.setStyle("Fusion")
    app.setStyleSheet(THEME)
    window = Window(engine, first_run=False)
    if args.smoke_research:
        window.navigation.setCurrentRow(PAGES.index("Research"))
    window.show()
    result = 1

    def capture():
        nonlocal result
        if window.worker:
            QTimer.singleShot(100, capture)
            return
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        saved = window.grab().save(str(capture_path))
        metrics = engine.db.metrics()
        verification = {"screenshot": saved, "metrics": metrics}
        total = sum(row["n"] for row in metrics["findings"])
        if args.smoke_research:
            run = engine.db.query("SELECT status,data FROM research_runs ORDER BY id DESC LIMIT 1")[
                0
            ]
            verification["research_status"] = run["status"]
            data = json.loads(run["data"])
            verification["index"] = data.get("index", {})
            verification["hypotheses"] = len(data.get("hypotheses", []))
            result = (
                0
                if saved
                and run["status"] == "completed"
                and verification["hypotheses"] == 1
                and verification["index"].get("parser_memory", {}).get("enforced")
                else 1
            )
        else:
            result = 0 if saved and total == 6 else 1
        capture_path.with_suffix(".json").write_text(
            json.dumps(verification, indent=2), encoding="utf-8"
        )
        window.close()
        app.quit()

    QTimer.singleShot(500, capture)
    QTimer.singleShot(30000, app.quit)
    app.exec()
    return result


if __name__ == "__main__":
    dispatch()
    prepare_runtime()
    raise SystemExit(main())
