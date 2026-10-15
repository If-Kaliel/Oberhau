import json
from pathlib import Path
from threading import Event

import pytest

from oberhau.core import OberhauError, Status
from oberhau.database import Database
from oberhau.engine import ASSETS, project_lock
from oberhau.laboratory import validate_sql
from oberhau.reporting import export, generate
from oberhau.scheduler import add_schedule, take_due


def test_real_pipeline_with_negative_control(engine, scanned, tmp_path):
    rows = engine.db.query("SELECT * FROM findings")
    assert len(rows) == 6
    assert all(json.loads(r["data"])["path"] == "vulnerable.py" for r in rows)
    assert "oberhau_fake_fixture_credential_123456" not in str(rows)
    sql = next(r for r in rows if json.loads(r["data"])["rule"] == "python-sql-format")
    investigation = engine.investigate(sql["id"])
    assert investigation["source_unchanged"]
    assert len(investigation["observations"]) == 1
    validation = validate_sql(engine.db, sql["id"])
    assert validation["passed"] and validation["fixed_rows"] == 0
    assert engine.db.finding(sql["id"])["status"] == Status.REPRODUCED
    engine.db.review(
        sql["id"], Status.VERIFIED, "Observed two rows; corrected query produced zero."
    )
    report_id, content = generate(engine.db, sql["id"])
    assert "Ready for Human Review" in content
    assert "observed_rows" in content
    for extension in ("md", "html", "json", "sarif"):
        target = tmp_path / f"report.{extension}"
        export(engine.db, report_id, target)
        assert target.stat().st_size > 100
        if extension in {"json", "sarif"}:
            json.loads(target.read_text())
    result = json.loads((tmp_path / "report.sarif").read_text())["runs"][0]["results"][0]
    finding = engine.db.finding(sql["id"])["finding"]
    levels = {"critical": "error", "high": "error", "medium": "warning"}
    assert result["level"] == levels.get(finding.severity, "note")
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": finding.line, "endLine": finding.end_line}


def test_deduplication_history_and_review_survival(engine, scanned):
    row = engine.db.query("SELECT id FROM findings LIMIT 1")[0]
    engine.db.review(row["id"], Status.FALSE_POSITIVE, "Protected by trusted data origin")
    engine.scan(scanned, "quick")
    assert len(engine.db.query("SELECT id FROM findings")) == 6
    assert engine.db.finding(row["id"])["status"] == Status.FALSE_POSITIVE
    assert engine.db.finding(row["id"])["occurrences"] == 2


def test_explicit_cross_engine_equivalence_keeps_raw_observations(engine, scanned):
    row = next(
        r
        for r in engine.db.query("SELECT * FROM findings")
        if json.loads(r["data"])["rule"] == "python-dynamic-code"
    )
    finding = engine.db.finding(row["id"])["finding"]
    finding.scanner = "semgrep"
    finding.rule = "namespace.oberhau-python-eval"
    assert engine.db.save_finding(scanned, row["last_scan"], finding) == row["id"]
    assert len(engine.db.query("SELECT * FROM findings")) == 6
    assert len(engine.db.query("SELECT * FROM observations WHERE finding_id=?", (row["id"],))) == 2
    assert engine.db.finding(row["id"])["occurrences"] == 1


def test_changed_scan_refresh_and_absence_not_automatically_fixed(engine, tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("eval(user_input)\n")
    project = engine.ingestion.add(source, "Example")
    engine.scan(project, "quick")
    unchanged = engine.scan(project, "changed")
    assert (
        engine.db.query("SELECT file_count FROM scans WHERE id=?", (unchanged,))[0]["file_count"]
        == 0
    )
    (source / "app.py").write_text("print('safe')\n")
    engine.ingestion.refresh(project)
    modified = engine.scan(project, "changed")
    assert (
        engine.db.query("SELECT file_count FROM scans WHERE id=?", (modified,))[0]["file_count"]
        == 1
    )
    assert len(engine.db.query("SELECT * FROM projects")) == 1
    assert engine.db.query("SELECT status FROM findings")[0]["status"] == Status.DETECTED


def test_cancelled_scan_has_auditable_status(engine, project):
    cancel = Event()
    cancel.set()
    scan = engine.scan(project, "quick", cancel)
    assert (
        engine.db.query("SELECT status FROM scans WHERE id=?", (scan,))[0]["status"] == "cancelled"
    )


def test_cancellation_during_scanner(engine, project):
    cancel = Event()

    def progress(message):
        if "inspected" in message:
            cancel.set()

    scan = engine.scan(project, "quick", cancel, progress)
    assert (
        engine.db.query("SELECT status FROM scans WHERE id=?", (scan,))[0]["status"] == "cancelled"
    )


def test_missing_tool_is_failed_not_success(engine, project, monkeypatch):
    monkeypatch.setattr("oberhau.security.shutil.which", lambda _: None)
    scan = engine.scan(project, "dependencies")
    assert engine.db.query("SELECT status FROM scans WHERE id=?", (scan,))[0]["status"] == "failed"


def test_duplicate_scan_lock(engine, project):
    with project_lock(engine.home, project):
        with pytest.raises(OberhauError, match="already running"):
            engine.scan(project, "quick")


def test_validation_cannot_run_arbitrary_imported_source(engine, tmp_path):
    project = engine.ingestion.add(ASSETS / "demo", "Real project", demo=False)
    engine.scan(project, "quick")
    sql = next(
        r
        for r in engine.db.query("SELECT id,data FROM findings")
        if json.loads(r["data"])["rule"] == "python-sql-format"
    )
    with pytest.raises(OberhauError, match="restricted"):
        validate_sql(engine.db, sql["id"])


def test_review_evidence_requirements(engine, scanned):
    finding = engine.db.query("SELECT id FROM findings LIMIT 1")[0]["id"]
    for status in (Status.VERIFIED, Status.READY, Status.FALSE_POSITIVE, Status.REPRODUCED):
        with pytest.raises(OberhauError):
            engine.db.review(finding, status, "")


def test_report_ai_fallback_and_redacted_edits(engine, scanned, tmp_path, monkeypatch):
    finding = engine.db.query("SELECT id FROM findings LIMIT 1")[0]["id"]

    def unavailable(*args, **kwargs):
        raise OberhauError("Local model unavailable")

    monkeypatch.setattr("oberhau.reporting.Ollama.draft", unavailable)
    report_id, body = generate(engine.db, finding, "pt-BR", ai=True)
    assert "incomplete" in body and "deterministic:fallback" in body
    output = tmp_path / "edited.html"
    export(engine.db, report_id, output, '<script>alert(1)</script>\npassword = "privatevalue123"')
    rendered = output.read_text()
    assert "<script>" not in rendered and "privatevalue123" not in rendered
    assert len(engine.db.query("SELECT * FROM reports")) == 2


def test_backup_restore_and_metrics(engine, scanned, tmp_path):
    target = tmp_path / "backup.sqlite3"
    engine.db.backup(target)
    with pytest.raises(OberhauError):
        engine.db.backup(target)
    restored = tmp_path / "restored.sqlite3"
    Database.restore(target, restored)
    assert Database(restored).metrics()["projects"] == 1
    with pytest.raises(OberhauError):
        Database.restore(target, restored)


def test_migration_failure_rolls_back(tmp_path, monkeypatch):
    monkeypatch.setattr("oberhau.database.MIGRATIONS", ["CREATE TABLE safe(id); INVALID SQL;"])
    with pytest.raises(OberhauError, match="migration"):
        Database(tmp_path / "broken.sqlite3")
    import sqlite3

    with sqlite3.connect(tmp_path / "broken.sqlite3") as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert not connection.execute("SELECT name FROM sqlite_master WHERE name='safe'").fetchall()


def test_scheduler_claims_once_and_rejects_active(engine, project):
    schedule = add_schedule(engine.db, project, "quick", 60)
    assert take_due(engine.db)["id"] == schedule
    assert take_due(engine.db) is None
    with pytest.raises(OberhauError):
        add_schedule(engine.db, project, "active", 1)


def test_trusted_plugin(engine, tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "example", Path(__file__).parents[1] / "examples/readme_plugin.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plugin = module.SecurityContactPlugin()
    engine.registry.register(plugin)
    root = tmp_path / "source"
    root.mkdir()
    (root / "README.md").write_text("Example")
    results = plugin.scan(root, ["README.md"], Event(), engine.limits, lambda _: None)
    assert len(results) == 1 and results[0].severity == "informative"


def test_file_is_not_executed(engine, tmp_path):
    source = tmp_path / "evil.py"
    marker = tmp_path / "executed"
    source.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n")
    project = engine.ingestion.add(source, "Untrusted")
    engine.scan(project, "quick")
    assert not marker.exists()
