import json
import os

import pytest

from oberhau.benchmark import evaluate
from oberhau.core import Cancelled, OberhauError
from oberhau.local_validation import validate_local

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.mark.parametrize("recipe,fixed_status", [("authorization", 403), ("input-validation", 400)])
def test_http_trusted_labs_store_observations_without_target_confirmation(
    engine, recipe, fixed_status
):
    result = validate_local(engine.db, recipe)
    assert result["passed"]
    assert result["observed"][0]["status"] == 200
    assert result["observed"][1]["status"] == fixed_status
    assert engine.db.query("SELECT finding_id FROM validations")[0]["finding_id"] is None
    assert not engine.db.query("SELECT id FROM findings")


def test_no_target_or_imported_recipe_execution(engine):
    from threading import Event

    with pytest.raises(OberhauError):
        validate_local(engine.db, "https://target.example")
    cancel = Event()
    cancel.set()
    with pytest.raises(Cancelled):
        validate_local(engine.db, "authorization", cancel)
    assert not engine.db.query("SELECT id FROM validations")


def test_benchmark_measurements_report_all_expected_and_detected_signals():
    result = evaluate()
    assert len(result["cases"]) == 12
    assert result["true_positives"] + result["false_negatives"] == sum(
        len(case["expected"]) for case in result["cases"]
    )
    assert result["seconds"] >= 0 and result["peak_python_bytes"] > 0
    assert "not representative" in result["limitations"]
    assert result["precision"] == result["true_positives"] / (
        result["true_positives"] + result["false_positives"]
    )


def test_research_gui_displays_actual_paths_queue_and_benchmark(engine, tmp_path):
    from PySide6.QtWidgets import QApplication

    from oberhau.desktop.app import PAGES, Window
    from tests.test_gui import wait_for_worker

    source = tmp_path / "app/resources"
    source.mkdir(parents=True)
    (source / "route.ts").write_text(
        "export function GET(req: Request, params: any) { return db.resource.findUnique({where:{id:params.id}}); }"
    )
    engine.ingestion.add(source, "Authorized UI fixture")
    app = QApplication.instance() or QApplication([])
    window = Window(engine, first_run=False)
    try:
        window.show()
        wait_for_worker(app, window)
        window.navigation.setCurrentRow(PAGES.index("Research"))
        page = window.research_page
        page.run()
        wait_for_worker(app, window)
        assert page.runs.count() == 1
        assert (
            "resource-authorization-context" in page.views["Investigation Workspace"].toPlainText()
        )
        assert "findUnique" in page.views["Code Flow Viewer"].toPlainText()
        assert "referenced-path" in page.views["Research Queue"].toPlainText()
        page.lab("authorization")
        wait_for_worker(app, window)
        assert '"recipe": "authorization"' in page.views["Investigation Workspace"].toPlainText()
        page.assistant(False)
        wait_for_worker(app, window)
        assert "deterministic" in page.views["AI Investigator"].toPlainText()
        page.benchmark()
        wait_for_worker(app, window)
        data = json.loads(page.views["Benchmark Dashboard"].toPlainText())
        assert len(data["cases"]) == 12
    finally:
        window.close()
        app.processEvents()
