"""Capture the native research page using actual, labeled synthetic research records."""

import json
import os
import sys
from pathlib import Path

if "--native" not in sys.argv:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from oberhau.benchmark import DATASET, evaluate
from oberhau.desktop.app import PAGES, Window, configure_fonts
from oberhau.desktop.theme import THEME
from oberhau.engine import Engine
from oberhau.local_validation import validate_local
from oberhau.reporting import export, generate
from oberhau.research_assistant import assist

root = Path(__file__).resolve().parents[1]
source = root / ".oberhau/directive002-smoke-source"
source.mkdir(exist_ok=True)
case = json.loads(DATASET.read_text())["cases"][3]
for relative, code in case["sources"].items():
    target = source / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code, encoding="utf-8")
engine = Engine(root / ".oberhau/directive002-native-smoke")
project = engine.ingestion.add(source, "DEMONSTRATION / CONTEXTUAL RESEARCH", demo=True)
scan = engine.scan(project, "research")
run = engine.db.query("SELECT id FROM research_runs ORDER BY id DESC LIMIT 1")[0]["id"]
assistant = assist(engine, run, ai="--ai" in sys.argv)
benchmark = evaluate()
engine.db.set_setting("last_research_benchmark", benchmark)
labs = [validate_local(engine.db, recipe) for recipe in ("authorization", "input-validation")]
finding = engine.db.query(
    "SELECT id FROM findings WHERE project_id=? AND json_extract(data,'$.scanner')='contextual'",
    (project,),
)[0]["id"]
report, _ = generate(engine.db, finding)
export(engine.db, report, root / "artifacts/directive002-report.md")
(root / "artifacts/directive002-benchmark.json").write_text(
    json.dumps(benchmark, indent=2), encoding="utf-8"
)
(root / "artifacts/directive002-smoke.json").write_text(
    json.dumps(
        {"project": project, "scan": scan, "run": run, "assistant": assistant, "labs": labs},
        indent=2,
    ),
    encoding="utf-8",
)

app = QApplication([])
configure_fonts()
app.setStyle("Fusion")
app.setStyleSheet(THEME)
window = Window(engine, first_run=False)
window.resize(1380, 880)
window.show()


def capture():
    if window.worker:
        QTimer.singleShot(100, capture)
        return
    window.navigation.setCurrentRow(PAGES.index("Research"))
    for name in ("Investigation Workspace", "Code Flow Viewer", "Benchmark Dashboard"):
        index = list(window.research_page.views).index(name)
        window.research_page.tabs.setCurrentIndex(index)
        app.processEvents()
        target = root / "artifacts" / ("research-" + name.lower().replace(" ", "-") + ".png")
        window.grab().save(str(target))
    window.close()
    app.quit()


QTimer.singleShot(500, capture)
QTimer.singleShot(30000, app.quit)
app.exec()
print(
    json.dumps(
        {
            "scan": scan,
            "run": run,
            "labs_passed": all(result["passed"] for result in labs),
            "assistant": assistant["generator"],
        }
    )
)
