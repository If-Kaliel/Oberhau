"""Render the real native desktop using an isolated, visibly labeled demonstration database."""

import os
import sys
from pathlib import Path

if "--native" not in sys.argv:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from oberhau.desktop.app import Window, configure_fonts
from oberhau.desktop.theme import THEME
from oberhau.engine import ASSETS, Engine
from oberhau.laboratory import validate_sql
from oberhau.reporting import generate

root = Path(__file__).resolve().parents[1]
engine = Engine(root / ".oberhau" / "visual-smoke")
if not engine.db.query("SELECT id FROM projects"):
    project = engine.ingestion.add(ASSETS / "demo", "DEMONSTRATION / LABORATORY", demo=True)
    engine.scan(project, "quick")
    row = engine.db.query(
        "SELECT id FROM findings WHERE json_extract(data,'$.rule')='python-sql-format'"
    )[0]
    validate_sql(engine.db, row["id"])
    generate(engine.db, row["id"])

app = QApplication([])
configure_fonts()
app.setStyle("Fusion")
app.setStyleSheet(THEME)
window = Window(engine, first_run=False)
window.show()


def capture():
    if window.worker:
        QTimer.singleShot(100, capture)
        return
    target = root / "artifacts"
    target.mkdir(exist_ok=True)
    window.grab().save(str(target / "desktop-overview.png"))
    window.navigation.setCurrentRow(4)
    window.findings_table.selectRow(0)
    window.inspect()
    window.grab().save(str(target / "desktop-investigations.png"))
    window.close()
    app.quit()


QTimer.singleShot(500, capture)
QTimer.singleShot(30000, app.quit)
app.exec()
