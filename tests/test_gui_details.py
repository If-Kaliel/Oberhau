import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPlainTextEdit, QTableWidget

from oberhau.desktop.app import Window


def test_project_diff_licenses_and_real_scanner_details(engine, tmp_path, monkeypatch):
    source = tmp_path / "source.py"
    source.write_text("eval(value)\n")
    project = engine.ingestion.add(source, "Snapshot details")
    engine.scan(project, "quick")
    source.write_text("print('corrected')\n")
    engine.refresh_project(project)
    app = QApplication.instance() or QApplication([])
    window = Window(engine, first_run=False)
    window.diagnostics_attempted = True
    window.show()
    app.processEvents()
    captured = {}
    monkeypatch.setattr(
        window, "text_dialog", lambda title, content: captured.update({title: content})
    )
    try:
        window.projects_table.selectRow(0)
        window.project_details()
        details = json.loads(captured["Project details"])
        assert details["metadata"]["previous_snapshot"]
        monkeypatch.setattr(
            "oberhau.desktop.app.QInputDialog.getText", lambda *a, **k: ("source.py", True)
        )
        window.compare_file()
        assert "+print('corrected')" in captured["Compare source file"]
        window.licenses()
        assert "LGPL version 3" in captured["Licenses"]
        window.scan_history.selectRow(0)

        def inspect_dialog(dialog):
            table = dialog.findChild(QTableWidget)
            assert table.rowCount() == 1 and table.item(0, 1).text() == "completed"
            text = dialog.findChild(QPlainTextEdit).toPlainText()
            assert json.loads(text)[0]["scanner"] == "builtin"
            return 0

        monkeypatch.setattr("oberhau.desktop.app.QDialog.exec", inspect_dialog)
        window.show_scanner_runs()
    finally:
        window.close()
        app.processEvents()
