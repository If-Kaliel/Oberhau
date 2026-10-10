"""Native packaged entry, with an explicit isolated smoke mode for release QA."""

import argparse
import json
from pathlib import Path

from oberhau.core import data_home
from oberhau.frozen import prepare_runtime


def main():
    parser = argparse.ArgumentParser(description="OBERHAU desktop")
    parser.add_argument("--home", type=Path, default=data_home())
    parser.add_argument(
        "--smoke", type=Path, help="Run a labeled demo in --home and save a screenshot"
    )
    args = parser.parse_args()
    if args.smoke is None:
        from oberhau.desktop.app import main as desktop

        return desktop(args.home)
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from oberhau.desktop.app import Window, configure_fonts
    from oberhau.desktop.theme import THEME
    from oberhau.engine import ASSETS, Engine

    engine = Engine(args.home)
    project = engine.ingestion.add(ASSETS / "demo", "DEMONSTRATION / PACKAGED QA", demo=True)
    engine.scan(project, "quick")
    app = QApplication([])
    configure_fonts()
    app.setStyle("Fusion")
    app.setStyleSheet(THEME)
    window = Window(engine, first_run=False)
    window.show()
    result = 1

    def capture():
        nonlocal result
        if window.worker:
            QTimer.singleShot(100, capture)
            return
        args.smoke.parent.mkdir(parents=True, exist_ok=True)
        saved = window.grab().save(str(args.smoke))
        metrics = engine.db.metrics()
        args.smoke.with_suffix(".json").write_text(
            json.dumps({"screenshot": saved, "metrics": metrics}, indent=2), encoding="utf-8"
        )
        total = sum(row["n"] for row in metrics["findings"])
        result = 0 if saved and total == 6 else 1
        window.close()
        app.quit()

    QTimer.singleShot(500, capture)
    QTimer.singleShot(30000, app.quit)
    app.exec()
    return result


if __name__ == "__main__":
    prepare_runtime()
    raise SystemExit(main())
