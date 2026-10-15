import json
import sqlite3
import threading
from contextlib import contextmanager
from threading import Event

import pytest

from oberhau.backup import create_backup, restore_backup
from oberhau.core import Finding, Status, now
from oberhau.database import MIGRATIONS, Database
from oberhau.engine import ASSETS, Engine


def dependency(
    scanner="osv-scanner", name="Django", version="2.2.0", path="requirements.txt", aliases=None
):
    return Finding(
        scanner=scanner,
        rule="PYSEC-2020-1" if scanner == "osv-scanner" else "CVE-2020-0001",
        category="dependencies",
        title="Package advisory",
        path=path,
        advisories=aliases or ["CVE-2020-0001", "PYSEC-2020-1"],
        evidence={
            "package": {"ecosystem": "PyPI", "name": name, "version": version},
            "source_sha256": "stable",
        },
    )


def test_zero_warning_scanner_is_auditable(engine):
    project = engine.ingestion.add(ASSETS / "demo/fixed.py", "Negative control")
    scan = engine.scan(project, "quick")
    row = engine.db.scanner_runs(scan)[0]
    assert row["scanner"] == "builtin" and row["status"] == "completed"
    # Sub-millisecond runs may round to zero; auditability comes from the persisted run.
    assert row["findings"] == 0 and row["duration"] >= 0
    assert row["started"] and row["finished"]
    assert json.loads(row["provenance"])["bundled"]
    assert not engine.db.query("SELECT * FROM findings")


def test_unavailable_scanners_and_partial_builtin(engine, project, monkeypatch, tmp_path):
    monkeypatch.setattr("oberhau.security.shutil.which", lambda _: None)
    scan = engine.scan(project, "deep")
    rows = engine.db.scanner_runs(scan)
    assert len(rows) == 5
    assert len([r for r in rows if r["status"] == "unavailable"]) == 4
    source = tmp_path / "broken.py"
    source.write_text("def broken(\n")
    broken = engine.ingestion.add(source, "Invalid syntax")
    row = engine.db.scanner_runs(engine.scan(broken, "quick"))[0]
    assert row["status"] == "partial" and "Python parse error" in row["errors"]


def test_scanner_failure_and_cancel_are_persisted(engine, project, monkeypatch):
    def failed(*a, **k):
        raise RuntimeError("Fixture scanner failure")

    monkeypatch.setattr("oberhau.scanners.builtin.BuiltinScanner.scan", failed)
    row = engine.db.scanner_runs(engine.scan(project, "quick"))[0]
    assert row["status"] == "failed" and "Fixture scanner failure" in row["errors"]
    cancel = Event()
    cancel.set()
    row = engine.db.scanner_runs(engine.scan(project, "quick", cancel))[0]
    assert row["status"] == "cancelled" and row["started"] is None


def test_explicit_advisory_alias_merges_same_package_and_keeps_both_observations(engine, project):
    scan = engine.db.execute(
        "INSERT INTO scans(project_id,profile,status,started) VALUES(?,'dependencies','completed',?)",
        (project, now()),
    )
    first = dependency()
    first_id = engine.db.save_finding(project, scan, first)
    engine.db.review(first_id, Status.FALSE_POSITIVE, "Not reachable in deployed application")
    second = dependency("trivy", name="django", aliases=["CVE-2020-0001"])
    second.evidence["package"]["ecosystem"] = ""
    second.evidence["package"]["purl"] = "pkg:pypi/django@2.2.0"
    assert engine.db.save_finding(project, scan, second) == first_id
    record = engine.db.finding(first_id)
    assert record["status"] == Status.FALSE_POSITIVE
    assert set(record["finding"].advisories) == {"CVE-2020-0001", "PYSEC-2020-1"}
    assert record["occurrences"] == 1
    assert len(engine.db.query("SELECT * FROM observations")) == 2
    assert len(engine.db.query("SELECT * FROM findings")) == 1
    # Another raw OSV advisory alias in the same scan survives correlation.
    third = dependency(aliases=["CVE-2020-0001", "GHSA-2222-3333-4444"])
    third.rule = "GHSA-2222-3333-4444"
    assert engine.db.save_finding(project, scan, third) == first_id
    assert len(engine.db.query("SELECT * FROM observations")) == 3


@pytest.mark.parametrize("different", ["package", "version", "manifest", "alias", "ecosystem"])
def test_dependency_boundaries_prevent_false_correlation(engine, project, different):
    scan = engine.db.execute(
        "INSERT INTO scans(project_id,profile,status,started) VALUES(?,'dependencies','completed',?)",
        (project, now()),
    )
    first = dependency()
    second = dependency("trivy")
    if different == "package":
        second.evidence["package"]["name"] = "Other-package"
    if different == "version":
        second.evidence["package"]["version"] = "3.0.0"
    if different == "manifest":
        second.path = "other/requirements.txt"
    if different == "alias":
        second.advisories = ["CVE-2020-9999"]
    if different == "ecosystem":
        second.evidence["package"]["ecosystem"] = "npm"
    assert engine.db.save_finding(project, scan, first) != engine.db.save_finding(
        project, scan, second
    )


@pytest.mark.parametrize("case", ["equivalent-rule", "advisory-alias"])
def test_parallel_scanners_correlate_without_racing(engine, project, case):
    # Scanner jobs run in parallel threads; pause both after the existence check to force the race.
    scan = engine.db.execute(
        "INSERT INTO scans(project_id,profile,status,started) VALUES(?,'deep','running',?)",
        (project, now()),
    )
    if case == "equivalent-rule":
        first = Finding(
            scanner="builtin",
            rule="python-dynamic-code",
            category="unsafe-code",
            title="Dynamic code evaluation",
            path="vulnerable.py",
            line=3,
        )
        second = first.model_copy(update={"scanner": "semgrep", "rule": "oberhau-python-eval"})
        assert first.fingerprint(project) == second.fingerprint(project)
    else:
        first, second = dependency(), dependency("trivy", aliases=["CVE-2020-0001"])
    barrier = threading.Barrier(2, timeout=0.5)
    original = engine.db.connect

    class Pausing:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, sql, *args):
            cursor = self.connection.execute(sql, *args)
            if sql.startswith("SELECT id,status,last_scan,data FROM findings"):
                try:
                    barrier.wait()
                except threading.BrokenBarrierError:
                    pass
            return cursor

    @contextmanager
    def connect():
        with original() as connection:
            yield Pausing(connection)

    engine.db.connect = connect
    errors = []

    def save(finding):
        try:
            engine.db.save_finding(project, scan, finding)
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=save, args=(f,)) for f in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    engine.db.connect = original
    assert not errors
    assert len(engine.db.query("SELECT * FROM findings")) == 1
    assert len(engine.db.query("SELECT * FROM observations")) == 2


def test_identical_advisory_for_two_packages_does_not_collide(engine, project):
    scan = engine.db.execute(
        "INSERT INTO scans(project_id,profile,status,started) VALUES(?,'dependencies','completed',?)",
        (project, now()),
    )
    assert engine.db.save_finding(project, scan, dependency()) != engine.db.save_finding(
        project, scan, dependency(name="Other-package")
    )


def test_previous_schema_and_research_bundle_upgrade(tmp_path):
    source_home = tmp_path / "old"
    source_home.mkdir()
    path = source_home / "oberhau.sqlite3"
    with sqlite3.connect(path) as connection:
        for migration in MIGRATIONS[:2]:
            connection.executescript(migration)
        connection.execute("PRAGMA user_version=2")
    # A known historical schema is accepted and upgraded, never an unknown schema.
    restored_db = tmp_path / "old-restored.sqlite3"
    Database.restore(path, restored_db)
    assert Database(restored_db).query("PRAGMA user_version")[0]["user_version"] == len(MIGRATIONS)
    old = Engine(source_home)
    project = old.ingestion.add(ASSETS / "demo", "Old research", demo=True)
    scan = old.scan(project, "quick")
    target = tmp_path / "bundle.zip"
    create_backup(old.db, old.home, target)
    home = tmp_path / "portable"
    restore_backup(target, home)
    recovered = Engine(home)
    assert recovered.db.scanner_runs(scan)[0]["findings"] == 6
    assert recovered.investigate(1)["source_unchanged"]
