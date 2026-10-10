import json
from threading import Event

import pytest

from oberhau.cli import main
from oberhau.core import Cancelled, OberhauError, Status
from oberhau.engine import ASSETS
from oberhau.scanners.builtin import BuiltinScanner


def test_cli_end_to_end(tmp_path, capsys, monkeypatch):
    home = str(tmp_path / "cli")
    prefix = ["--home", home]
    monkeypatch.setattr("oberhau.security.shutil.which", lambda _: None)
    assert main(prefix + ["demo"]) == 0
    result = json.loads(capsys.readouterr().out)
    project = str(result["project"])
    assert main(prefix + ["projects"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["demo"] == 1
    assert main(prefix + ["findings", "--project", project]) == 0
    findings = json.loads(capsys.readouterr().out)
    sql = str(
        next(f["id"] for f in findings if json.loads(f["data"])["rule"] == "python-sql-format")
    )
    assert main(prefix + ["investigate", sql]) == 0
    capsys.readouterr()
    assert main(prefix + ["validate", sql]) == 0
    capsys.readouterr()
    assert (
        main(
            prefix
            + ["review", sql, "--status", "Human Verified", "--notes", "Observed fixture evidence."]
        )
        == 0
    )
    capsys.readouterr()
    assert main(prefix + ["report", sql, "--output", str(tmp_path / "report.md")]) == 0
    capsys.readouterr()
    assert main(prefix + ["metrics"]) == 0
    assert json.loads(capsys.readouterr().out)["reports"] == 1
    assert main(prefix + ["schedule", project]) == 0
    capsys.readouterr()
    assert main(prefix + ["backup", str(tmp_path / "backup.db")]) == 0
    capsys.readouterr()
    assert (
        main(prefix + ["restore", str(tmp_path / "backup.db"), str(tmp_path / "restored.db")]) == 0
    )
    capsys.readouterr()
    assert main(prefix + ["refresh", project]) == 0
    capsys.readouterr()
    assert main(prefix + ["scan", project, "--profile", "quick"]) == 0
    capsys.readouterr()
    assert main(prefix + ["scan", project, "--profile", "dependencies"]) == 2
    capsys.readouterr()
    assert main(prefix + ["add", str(ASSETS / "demo/fixed.py"), "--name", "Safe"]) == 0
    capsys.readouterr()
    assert main(prefix + ["add", str(tmp_path / "missing"), "--name", "Missing"]) == 1


def test_cli_diagnostics(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("oberhau.diagnostics.Ollama.models", lambda _: ["qwen3.5:4b"])
    monkeypatch.setattr("oberhau.diagnostics.capabilities", lambda _: [])
    assert main(["--home", str(tmp_path / "cli"), "diagnostics"]) == 0
    assert json.loads(capsys.readouterr().out)["qwen_available"]


def test_scanner_failure_does_not_report_success(engine, project, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("Unexpected plugin failure")

    monkeypatch.setattr(BuiltinScanner, "scan", broken)
    scan = engine.scan(project, "quick")
    record = engine.db.query("SELECT * FROM scans WHERE id=?", (scan,))[0]
    assert record["status"] == "failed"
    assert "Unexpected plugin failure" in record["errors"]


def test_parse_error_keeps_partial_coverage_record(engine, tmp_path):
    source = tmp_path / "invalid.py"
    source.write_text("def not_valid(\n")
    project = engine.ingestion.add(source, "Invalid Python")
    scan = engine.scan(project, "quick")
    record = engine.db.query("SELECT * FROM scans WHERE id=?", (scan,))[0]
    assert record["status"] == "partial" and "parse error" in record["errors"]


def test_changes_reopen_human_decision(engine, tmp_path):
    source = tmp_path / "warning.py"
    source.write_text("eval(input_value)\n")
    project = engine.ingestion.add(source, "Changing source")
    engine.scan(project, "quick")
    finding = engine.db.query("SELECT id FROM findings")[0]["id"]
    engine.db.review(finding, Status.FALSE_POSITIVE, "Old data origin was trusted")
    source.write_text("eval(other_input)\n")
    engine.ingestion.refresh(project)
    engine.scan(project, "quick")
    assert engine.db.finding(finding)["status"] == Status.SUSPECTED


def test_import_cancellation_leaves_no_partial_snapshot(engine):
    cancel = Event()
    cancel.set()
    with pytest.raises(Cancelled):
        engine.ingestion.add(ASSETS / "demo", "Cancelled import", cancel=cancel)
    assert not engine.db.query("SELECT * FROM projects")


def test_unknown_profile_and_plugin_permissions(engine, project):
    with pytest.raises(OberhauError):
        engine.scan(project, "active")
    plugin = BuiltinScanner()
    with pytest.raises(OberhauError):
        engine.registry.register(plugin)
    plugin.identifier = "network-plugin"
    plugin.network = True
    with pytest.raises(OberhauError):
        engine.registry.register(plugin)
