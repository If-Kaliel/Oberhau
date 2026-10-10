import hashlib
import json
from threading import Event

import pytest

from oberhau.core import Cancelled, OberhauError, Status, now
from oberhau.engine import Engine
from oberhau.maintenance import maintain, usage


def research_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "route.ts").write_text(
        "export function GET(req:Request, params:any) { return db.user.findUnique({where:{id:params.id}}); }"
    )
    return source


def test_retention_preserves_historical_symbols_evidence_and_human_reviews(engine, tmp_path):
    from oberhau.research_assistant import ResearchTools

    project = engine.ingestion.add(research_source(tmp_path), "Retention")
    engine.scan(project, "research")
    run = engine.db.query("SELECT id FROM research_runs")[0]["id"]
    finding = engine.db.query("SELECT id FROM findings")[0]["id"]
    engine.db.review(finding, Status.FALSE_POSITIVE, "Public resource: documented human decision")
    original = ResearchTools(engine, run).symbols_for_file("route.ts")
    engine.db.execute(
        "INSERT INTO research_files VALUES(?,?,?,?,?)",
        (project, "orphan.ts", "unused", "old", '{"orphan":true}'),
    )
    before = usage(engine.db)
    preview = maintain(engine)
    assert preview["eligible_records"] == 1 and usage(engine.db) == before
    result = maintain(engine, True)
    assert result["eligible_records"] == 1
    assert result["after"]["cache_bytes"] < before["cache_bytes"]
    assert ResearchTools(engine, run).symbols_for_file("route.ts") == original
    assert engine.db.finding(finding)["status"] == Status.FALSE_POSITIVE
    assert engine.db.finding(finding)["notes"] == "Public resource: documented human decision"
    assert engine.managed_snapshot(ResearchTools(engine, run).root.as_posix()).exists()


def test_cache_maintenance_cancel_is_transactional(engine, tmp_path):
    project = engine.ingestion.add(research_source(tmp_path), "Cache cancellation")
    engine.db.execute(
        "INSERT INTO research_files VALUES(?,?,?,?,?)",
        (project, "orphan.ts", "unused", "old", "{}"),
    )
    cancel = Event()
    cancel.set()
    with pytest.raises(Cancelled):
        maintain(engine, True, cancel)
    assert usage(engine.db)["cache_records"] == 1


@pytest.mark.parametrize("budget", ["cache_bytes", "history_bytes", "runs_per_project"])
def test_research_storage_admission_stops_without_partial_hypotheses(engine, tmp_path, budget):
    project = engine.ingestion.add(research_source(tmp_path), "Budget")
    if budget == "runs_per_project":
        engine.scan(project, "research")
        engine.db.set_setting("retention_limits", {budget: 1})
    else:
        engine.db.set_setting("retention_limits", {budget: 1000})
    before = len(engine.db.query("SELECT id FROM observations"))
    engine.scan(project, "research")
    latest = engine.db.query("SELECT * FROM scans ORDER BY id DESC LIMIT 1")[0]
    assert latest["status"] != "completed"
    assert len(engine.db.query("SELECT id FROM observations")) == before
    assert "budget" in latest["errors"].lower() or "retention limit" in latest["errors"]


def test_startup_marks_abandoned_jobs_but_preserves_completed_history(engine, tmp_path):
    project = engine.ingestion.add(research_source(tmp_path), "Recovery")
    engine.scan(project, "research")
    scan = engine.db.execute(
        "INSERT INTO scans(project_id,profile,status,started) VALUES(?,'research','running',?)",
        (project, now()),
    )
    engine.db.execute(
        "INSERT INTO research_runs(project_id,scan_id,status,started) VALUES(?,?,'running',?)",
        (project, scan, now()),
    )
    engine.db.execute(
        "INSERT INTO scanner_runs(scan_id,scanner,status) VALUES(?,'builtin','pending')", (scan,)
    )
    reopened = Engine(engine.home)
    for table in ("scans", "research_runs", "scanner_runs"):
        assert (
            reopened.db.query(f"SELECT status FROM {table} ORDER BY id DESC LIMIT 1")[0]["status"]
            == "interrupted"
        )
        assert (
            reopened.db.query(f"SELECT COUNT(*) AS n FROM {table} WHERE status='completed'")[0]["n"]
            > 0
        )


def test_indexing_deadline_prevents_unbounded_walk(engine, tmp_path, monkeypatch):
    from oberhau.ingestion import file_index

    source = research_source(tmp_path)
    ticks = iter([0, 200])
    monkeypatch.setattr("oberhau.ingestion.time.monotonic", lambda: next(ticks))
    with pytest.raises(OberhauError, match="deadline"):
        file_index(source, engine.limits, Event())


def test_research_ui_filter_pagination_source_navigation_and_json_opt_in(engine, tmp_path):
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QDialog, QPlainTextEdit

    from oberhau.desktop.app import Window
    from tests.test_gui import wait_for_worker

    project = engine.ingestion.add(research_source(tmp_path), "UI release")
    engine.scan(project, "research")
    app = QApplication.instance() or QApplication([])
    window = Window(engine, first_run=False)
    try:
        wait_for_worker(app, window)
        page = window.research_page
        page.refresh()
        view = page.views["Investigation Workspace"]
        assert not view.technical.isChecked() and not view.detail.toPlainText().startswith("{")
        hypothesis = view.tree.topLevelItem(0)
        assert hypothesis.childCount() > 0 and view.open.isEnabled()
        view.filter.setText("nonexistent-file")
        assert view.tree.topLevelItemCount() == 0 and not view.open.isEnabled()
        view.filter.clear()
        captured = []

        def close_excerpt():
            dialog = app.activeModalWidget()
            assert isinstance(dialog, QDialog)
            captured.append(dialog.findChild(QPlainTextEdit).toPlainText())
            dialog.reject()

        QTimer.singleShot(50, close_excerpt)
        view.open_selected()
        assert "findUnique" in captured[0] and "1:" in captured[0]
        view.technical.setChecked(True)
        assert json.loads(view.detail.toPlainText())["hypotheses"]
        source = engine.managed_snapshot(engine.ingestion.project(project)["root"]) / "route.ts"
        source.write_text("changed source")
        with pytest.raises(OberhauError, match="integrity"):
            view.open_selected()
        rows = [([f"row-{i}", "", "", ""], {"id": i}, None, []) for i in range(450)]
        view.render({"actual": 450}, rows)
        assert view.tree.topLevelItemCount() == 200 and view.next.isEnabled()
        view.turn(200)
        assert view.tree.topLevelItem(0).text(0) == "row-200"
        view.filter.setText("row-449")
        assert view.tree.topLevelItemCount() == 1 and not view.next.isEnabled()
    finally:
        wait_for_worker(app, window)
        window.close()
        app.processEvents()


def test_external_dataset_labels_and_sources_are_frozen_before_scoring():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    labels = json.loads((root / "evaluation/external-labels.json").read_text())
    sources = json.loads((root / "evaluation/external-sources.json").read_text())
    assert len(labels["cases"]) == 60
    assert any(not case["positive"] for case in labels["cases"])
    assert len(sources["files"]) >= 24
    assert all(
        len(file["revision"]) == 40 and len(file["sha256"]) == 64 for file in sources["files"]
    )
    assert (
        hashlib.sha256((root / "evaluation/external-labels.json").read_bytes()).hexdigest()
        == "fd649e2f5bc85e01c7b68d2af71997cda97ffe3870c0f9c186f1830525799c2d"
    )


def test_literal_formatting_and_implicit_shell_helpers_keep_safe_controls(tmp_path):
    from oberhau.core import Limits
    from oberhau.scanners.builtin import BuiltinScanner

    (tmp_path / "controls.py").write_text("""import subprocess
cur.execute("SELECT {}".format(user_input))
cur.execute("SELECT [VALUE]".replace("[VALUE]", user_input))
cur.execute("SELECT ?", (user_input,))
cur.execute(formatter.format(user_input))
subprocess.getoutput(user_input)
subprocess.getstatusoutput(user_input)
subprocess.run(user_input, shell=1)
subprocess.run([user_input], shell=False)
subprocess.run([user_input], shell=0)
""")
    findings = BuiltinScanner().scan(tmp_path, ["controls.py"], Event(), Limits(), lambda _: None)
    assert {(f.line, f.rule) for f in findings} == {
        (2, "python-sql-format"),
        (3, "python-sql-format"),
        (6, "python-shell"),
        (7, "python-shell"),
        (8, "python-shell"),
    }


def test_database_only_backup_restore_release_windows_file_handles(engine, tmp_path):
    from oberhau.database import Database

    backup = tmp_path / "backup.sqlite3"
    engine.db.backup(backup)
    moved = backup.replace(tmp_path / "moved.sqlite3")
    restored = tmp_path / "restored.sqlite3"
    Database.restore(moved, restored)
    renamed = restored.replace(tmp_path / "renamed.sqlite3")
    reopened = Database(renamed)
    assert reopened.query("PRAGMA user_version")[0]["user_version"] == 4


def test_first_launch_setup_demo_and_reopen_preserve_user_choices(engine):
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QSpinBox

    from oberhau.desktop.app import Window
    from tests.test_gui import wait_for_worker

    app = QApplication.instance() or QApplication([])
    window = Window(engine, first_run=True)
    choices = []

    def choose_setup():
        dialog = app.activeModalWidget()
        assert isinstance(dialog, QDialog)
        dialog.findChild(QSpinBox).setValue(1)
        dialog.findChild(QCheckBox).setChecked(True)
        choices.append(True)
        dialog.accept()

    QTimer.singleShot(125, choose_setup)
    try:
        window.show()
        wait_for_worker(app, window)
        assert choices and engine.db.setting("setup_complete")
        assert engine.db.setting("limits")["parallelism"] == 1
        assert not engine.db.setting("schedules_enabled", False)
        assert window.findings_table.rowCount() == 6
    finally:
        window.close()
        app.processEvents()
    reopened = Window(Engine(engine.home), first_run=True)
    try:
        wait_for_worker(app, reopened)
        assert reopened.findings_table.rowCount() == 6
        assert reopened.parallelism.value() == 1
        assert app.activeModalWidget() is None
    finally:
        reopened.close()
        app.processEvents()
