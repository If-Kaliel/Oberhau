import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from oberhau.desktop.app import PAGES, Window, configure_fonts
from oberhau.desktop.theme import THEME


def wait_for_worker(app, window):
    deadline = time.monotonic() + 30
    # Allow the delayed startup diagnostics to run as well.
    while time.monotonic() < deadline:
        app.processEvents()
        if window.worker is None and window.diagnostics_attempted:
            return
        time.sleep(0.01)
    raise AssertionError("Qt background operation did not finish")


def test_gui_research_backup_restore_and_open(engine, scanned, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = Window(engine, first_run=False)
    window.show()
    wait_for_worker(app, window)
    target = tmp_path / "gui.oberhau.zip"
    monkeypatch.setattr(
        "oberhau.desktop.app.QFileDialog.getSaveFileName", lambda *a, **k: (str(target), "")
    )
    window.backup()
    wait_for_worker(app, window)
    assert target.is_file()
    monkeypatch.setattr(
        "oberhau.desktop.app.QFileDialog.getOpenFileName", lambda *a, **k: (str(target), "")
    )
    monkeypatch.setattr(
        "oberhau.desktop.app.QFileDialog.getExistingDirectory", lambda *a, **k: str(tmp_path)
    )
    monkeypatch.setattr(
        "oberhau.desktop.app.QInputDialog.getText", lambda *a, **k: ("gui-recovered", True)
    )
    window.restore()
    wait_for_worker(app, window)
    recovered = tmp_path / "gui-recovered"
    assert (recovered / "oberhau.sqlite3").exists()
    monkeypatch.setattr(
        "oberhau.desktop.app.QFileDialog.getExistingDirectory", lambda *a, **k: str(recovered)
    )
    window.open_data_directory()
    replacement = window.replacement
    try:
        wait_for_worker(app, replacement)
        assert replacement.engine.home == recovered
        assert replacement.findings_table.rowCount() == 6
        assert replacement.engine.investigate(1)["source_unchanged"]
        assert not window.isVisible()
    finally:
        replacement.close()
        window.close()
        app.processEvents()


def test_native_ui_navigation_real_data_and_worker(engine, scanned):
    app = QApplication.instance() or QApplication([])
    configure_fonts()
    app.setStyleSheet(THEME)
    window = Window(engine, first_run=False)
    window.show()
    app.processEvents()
    assert window.projects_table.rowCount() == 1
    assert window.findings_table.rowCount() == 6
    for index in range(len(PAGES)):
        window.navigation.setCurrentRow(index)
        app.processEvents()
        assert window.stack.currentIndex() == index
    deadline = time.monotonic() + 30
    while window.worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    # Start an actual shared-engine scan from a Qt background worker.
    window.scan_profile.setCurrentText("quick")
    window.run_scan()
    while window.worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert window.worker is None
    assert engine.db.metrics()["scans"] == 2
    window.findings_table.selectRow(0)
    window.inspect()
    assert "Source integrity" in window.investigation_text.toPlainText()
    window.make_report(False)
    while window.worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert window.report_id is not None
    window.close()
    app.processEvents()
