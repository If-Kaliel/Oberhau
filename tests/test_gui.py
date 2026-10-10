import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from oberhau.desktop.app import PAGES, Window, configure_fonts
from oberhau.desktop.theme import THEME


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
