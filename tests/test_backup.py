import hashlib
import json
import os
import shutil
import sqlite3
import stat
import zipfile
from pathlib import Path
from threading import Event, Thread

import pytest

from oberhau.backup import BackupLimits, create_backup, publish_restore, restore_backup
from oberhau.cli import main
from oberhau.core import Cancelled, OberhauError, Status, now
from oberhau.engine import ASSETS, Engine
from oberhau.laboratory import validate_sql
from oberhau.reporting import generate
from oberhau.scheduler import add_schedule
from oberhau.storage import store_lock


@pytest.fixture
def bundle(engine, scanned, tmp_path):
    target = tmp_path / "research.oberhau.zip"
    create_backup(engine.db, engine.home, target)
    return target


def rewrite_bundle(source, destination, mutate):
    with zipfile.ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(files.pop("manifest.json"))
    mutate(files, manifest)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("manifest.json", json.dumps(manifest))
    return destination


def test_portable_research_round_trip_including_historical_evidence(engine, tmp_path):
    source = tmp_path / "source"
    shutil.copytree(ASSETS / "demo", source)
    project = engine.ingestion.add(source, "Demonstration", demo=True)
    engine.scan(project, "quick")
    finding = engine.db.query(
        "SELECT id FROM findings WHERE json_extract(data,'$.rule')='python-sql-format'"
    )[0]["id"]
    assert validate_sql(engine.db, finding)["passed"]
    engine.db.review(finding, Status.VERIFIED, "Laboratory evidence reviewed")
    report_id, content = generate(engine.db, finding)
    engine.db.execute(
        "INSERT INTO rewards(finding_id,amount,hours,outcome,created) VALUES(?,?,?,?,?)",
        (finding, 25, 2, "accepted", now()),
    )
    engine.db.set_setting("language", "pt-BR")
    engine.db.set_setting("schedules_enabled", True)
    engine.db.set_setting("last_diagnostics", {"old_computer": True})
    add_schedule(engine.db, project, "quick", 60)
    old_root = Path(engine.ingestion.project(project)["root"])
    (old_root / "empty/nested").mkdir(parents=True)
    (source / "vulnerable.py").write_text("print('changed external source')\n")
    engine.ingestion.refresh(project)
    current_root = Path(engine.ingestion.project(project)["root"])
    for excluded in ("cache", "tools", "logs"):
        directory = engine.home / excluded
        directory.mkdir(exist_ok=True)
        (directory / "excluded.txt").write_text("MUST NOT BE IN BACKUP")
    before = engine.db.metrics()
    target = tmp_path / "complete.zip"
    result = create_backup(engine.db, engine.home, target)
    assert result["snapshots"] == 2
    with zipfile.ZipFile(target) as archive:
        assert not any(
            name.startswith(("tools/", "cache/", "logs/")) for name in archive.namelist()
        )
        manifest = json.loads(archive.read("manifest.json"))
        assert all(name.startswith("projects/") for name in manifest["snapshots"])
        assert (
            archive.read(old_root.relative_to(engine.home).as_posix() + "/vulnerable.py")
            == (old_root / "vulnerable.py").read_bytes()
        )
    # Prove recovery does not depend on the original home, including historical evidence.
    moved = tmp_path / "original-unavailable"
    # Keep the original-home-unavailable assertion, allowing bounded Windows sharing
    # contention in the setup rename just as the production restore publication does.
    publish_restore(engine.home, moved, Event())
    recovered_home = tmp_path / "recovered"
    restore_backup(target, recovered_home)
    recovered = Engine(recovered_home)
    assert recovered.db.metrics() == before
    assert recovered.db.finding(finding)["status"] == Status.VERIFIED
    assert recovered.db.finding(finding)["notes"] == "Laboratory evidence reviewed"
    assert (
        recovered.db.query("SELECT content FROM reports WHERE id=?", (report_id,))[0]["content"]
        == content
    )
    assert json.loads(recovered.db.query("SELECT result FROM validations")[0]["result"])["passed"]
    assert recovered.investigate(finding)["source_unchanged"]
    assert (recovered_home / old_root.relative_to(engine.home) / "empty/nested").is_dir()
    assert Path(
        recovered.ingestion.project(project)["root"]
    ) == recovered_home / current_root.relative_to(engine.home)
    for row in recovered.db.query("SELECT data FROM observations"):
        assert Path(json.loads(row["data"])["evidence"]["snapshot"]).is_relative_to(recovered_home)
    assert recovered.db.setting("schedules_enabled") is False
    assert recovered.db.setting("last_diagnostics") is None
    assert recovered.db.query("SELECT enabled FROM schedules")[0]["enabled"] == 0
    with pytest.raises(OberhauError, match="relinked"):
        recovered.ingestion.refresh(project)
    recovered.ingestion.relink(project, source)
    recovered.ingestion.refresh(project)
    scan = recovered.scan(project, "quick")
    assert (
        recovered.db.query("SELECT status FROM scans WHERE id=?", (scan,))[0]["status"]
        == "completed"
    )


def test_complete_cli_backup_restore_and_relink(engine, scanned, tmp_path, capsys):
    target, restored, unrelated = tmp_path / "cli.zip", tmp_path / "restored", tmp_path / "unused"
    assert main(["--home", str(engine.home), "backup", str(target), "--complete"]) == 0
    result = capsys.readouterr()
    assert json.loads(result.out)["snapshots"] == 1
    assert "Backed up" in result.err
    assert (
        main(["--home", str(unrelated), "restore", str(target), str(restored), "--complete"]) == 0
    )
    assert json.loads(capsys.readouterr().out)["schedules_paused"]
    assert not unrelated.exists()
    assert main(["--home", str(restored), "relink", str(scanned), str(ASSETS / "demo")]) == 0
    assert json.loads(capsys.readouterr().out)["relinked"] == scanned


def test_new_destinations_only(engine, bundle, tmp_path):
    original = bundle.read_bytes()
    with pytest.raises(OberhauError):
        create_backup(engine.db, engine.home, bundle)
    assert bundle.read_bytes() == original
    destination = tmp_path / "existing"
    destination.mkdir()
    marker = destination / "keep.txt"
    marker.write_text("keep")
    with pytest.raises(OberhauError):
        restore_backup(bundle, destination)
    assert marker.read_text() == "keep"


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_cancellation_removes_partial_work(engine, bundle, tmp_path, operation):
    cancel = Event()
    destination = tmp_path / operation

    def progress(_):
        cancel.set()

    with pytest.raises(Cancelled):
        if operation == "backup":
            create_backup(engine.db, engine.home, destination, cancel, progress)
        else:
            restore_backup(bundle, destination, cancel, progress)
    assert not destination.exists()
    assert not list(tmp_path.glob("oberhau-backup-*"))
    assert not list(tmp_path.glob("oberhau-restore-*"))


def test_scan_import_backup_exclusion_across_threads(engine, scanned, tmp_path):
    ready, release = Event(), Event()

    def hold_lock():
        with store_lock(engine.home):
            ready.set()
            release.wait(10)

    thread = Thread(target=hold_lock)
    thread.start()
    try:
        assert ready.wait(5)
        for operation in (
            lambda: engine.scan(scanned, "quick"),
            lambda: engine.ingestion.refresh(scanned),
            lambda: engine.ingestion.add(ASSETS / "demo", "Busy"),
            lambda: create_backup(engine.db, engine.home, tmp_path / "blocked.zip"),
            lambda: Engine(engine.home),
        ):
            with pytest.raises(OberhauError, match="using this data directory"):
                operation()
        assert len(engine.db.query("SELECT * FROM scans")) == 1
        assert len(engine.db.query("SELECT * FROM projects")) == 1
        assert not (tmp_path / "blocked.zip").exists()
    finally:
        release.set()
        thread.join(10)


def test_missing_retained_snapshot_refuses_incomplete_backup(engine, scanned, tmp_path):
    root = Path(engine.ingestion.project(scanned)["root"])
    root.rename(root.with_name("renamed-snapshot"))
    target = tmp_path / "incomplete.zip"
    with pytest.raises(OberhauError, match="missing or unsafe"):
        create_backup(engine.db, engine.home, target)
    assert not target.exists()


@pytest.mark.parametrize(
    "mutation", ["checksum", "missing", "extra", "format", "schema", "directories"]
)
def test_corrupt_or_inconsistent_archives_are_rejected(bundle, tmp_path, mutation):
    def mutate(files, manifest):
        path = next(name for name in files if name.startswith("projects/"))
        if mutation == "checksum":
            files[path] = bytes([files[path][0] ^ 1]) + files[path][1:]
        elif mutation == "missing":
            del files[path]
        elif mutation == "extra":
            files["extra.txt"] = b"undeclared"
        elif mutation == "format":
            manifest["version"] = 9000
        elif mutation == "schema":
            manifest["database_schema"] = 9000
        else:
            manifest["directories"] = []

    bad = rewrite_bundle(bundle, tmp_path / "bad.zip", mutate)
    target = tmp_path / "never-published"
    with pytest.raises(OberhauError):
        restore_backup(bad, target)
    assert not target.exists()


@pytest.mark.parametrize(
    "name",
    [
        "../escape.txt",
        "C:/escape.txt",
        "projects\\bad.txt",
        "NUL",
        "projects/a/./x",
        "projects/a//x",
        "projects/a/file. ",
    ],
)
def test_unsafe_archive_paths(bundle, tmp_path, name):
    bad = rewrite_bundle(
        bundle, tmp_path / "unsafe.zip", lambda files, _: files.update({name: b"bad"})
    )
    with pytest.raises(OberhauError):
        restore_backup(bad, tmp_path / "rejected")
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFDIR])
def test_special_archive_members_are_rejected(bundle, tmp_path, mode):
    bad = tmp_path / "special.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(bad, "w") as target:
        for original in source.infolist():
            entry = zipfile.ZipInfo(original.filename)
            entry.create_system = 3
            entry.external_attr = (mode | 0o600) << 16
            target.writestr(entry, source.read(original))
    with pytest.raises(OberhauError):
        restore_backup(bad, tmp_path / "rejected")


def test_case_collision_is_rejected(bundle, tmp_path):
    def mutate(files, _):
        path = next(name for name in files if name.startswith("projects/"))
        files[path.upper()] = files[path]

    bad = rewrite_bundle(bundle, tmp_path / "collision.zip", mutate)
    with pytest.raises(OberhauError, match="Duplicate"):
        restore_backup(bad, tmp_path / "rejected")


def test_unsupported_zip_compression_is_rejected(bundle, tmp_path):
    data = bytearray(bundle.read_bytes())
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    data[local + 8 : local + 10] = (99).to_bytes(2, "little")
    data[central + 10 : central + 12] = (99).to_bytes(2, "little")
    bad = tmp_path / "compression.zip"
    bad.write_bytes(data)
    with pytest.raises(OberhauError, match="compression"):
        restore_backup(bad, tmp_path / "rejected")


@pytest.mark.parametrize("mutation", ["trigger", "version", "snapshot", "foreign-key"])
def test_rehashed_untrusted_database_is_rejected(bundle, tmp_path, mutation):
    def mutate(files, manifest):
        path = tmp_path / "edited.sqlite3"
        path.write_bytes(files["oberhau.sqlite3"])
        with sqlite3.connect(path) as connection:
            if mutation == "trigger":
                connection.execute(
                    "CREATE TRIGGER altered AFTER UPDATE ON projects BEGIN DELETE FROM findings; END"
                )
            elif mutation == "version":
                connection.execute("PRAGMA user_version=9000")
            elif mutation == "snapshot":
                connection.execute("UPDATE projects SET root='../outside'")
            else:
                connection.execute("UPDATE findings SET project_id=99999")
        data = path.read_bytes()
        files["oberhau.sqlite3"] = data
        manifest["files"]["oberhau.sqlite3"] = {
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    bad = rewrite_bundle(bundle, tmp_path / "database.zip", mutate)
    with pytest.raises(OberhauError):
        restore_backup(bad, tmp_path / "rejected")


def test_restore_publication_race_preserves_existing_directory(bundle, tmp_path):
    target = tmp_path / "race"

    def progress(_):
        if not target.exists():
            target.mkdir()
            (target / "marker").write_text("preserve")

    with pytest.raises(OberhauError, match="another operation"):
        restore_backup(bundle, target, progress=progress)
    assert (target / "marker").read_text() == "preserve"


def test_resource_limits_reject_backup_and_restore(engine, bundle, tmp_path):
    with pytest.raises(OberhauError):
        create_backup(
            engine.db,
            engine.home,
            tmp_path / "small.zip",
            limits=BackupLimits(max_database_bytes=10),
        )
    with pytest.raises(OberhauError):
        restore_backup(bundle, tmp_path / "small", limits=BackupLimits(max_source_bytes=10))
    assert not (tmp_path / "small.zip").exists()
    assert not (tmp_path / "small").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows transient sharing/access errors")
@pytest.mark.parametrize("mode", ["temporary", "destination-race", "cancel"])
def test_restore_publication_retry_preserves_verification_destination_and_cancellation(
    bundle, tmp_path, monkeypatch, mode
):
    destination = tmp_path / "recovered"
    original = Path.rename
    cancel = Event()
    attempts = []

    def contended_rename(stage, target):
        if stage.name == "data" and target == destination:
            attempts.append(stage)
            if len(attempts) == 1:
                if mode == "destination-race":
                    destination.mkdir()
                    (destination / "keep.txt").write_text("existing user data")
                elif mode == "cancel":
                    cancel.set()
                error = PermissionError("Simulated transient Windows directory handle")
                error.winerror = 5
                raise error
        return original(stage, target)

    monkeypatch.setattr(Path, "rename", contended_rename)
    if mode == "temporary":
        restore_backup(bundle, destination, cancel)
        assert len(attempts) == 2
        assert Engine(destination).db.query("SELECT id FROM findings")
    elif mode == "destination-race":
        with pytest.raises(OberhauError, match="appeared"):
            restore_backup(bundle, destination, cancel)
        assert (destination / "keep.txt").read_text() == "existing user data"
        assert not (destination / "oberhau.sqlite3").exists()
    else:
        with pytest.raises(Cancelled):
            restore_backup(bundle, destination, cancel)
        assert not destination.exists()


def test_recovery_handles_large_history_and_interrupted_scan(engine, scanned, tmp_path):
    base = engine.db.query("SELECT * FROM findings LIMIT 1")[0]
    with engine.db.connect() as connection:
        for index in range(140):
            cursor = connection.execute(
                "INSERT INTO findings(project_id,fingerprint,data,status,first_scan,last_scan,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (
                    scanned,
                    f"history-{index}",
                    base["data"],
                    base["status"],
                    base["first_scan"],
                    base["last_scan"],
                    now(),
                    now(),
                ),
            )
            connection.execute(
                "INSERT INTO observations(finding_id,scan_id,scanner,rule,data) VALUES(?,?,?,?,?)",
                (cursor.lastrowid, base["first_scan"], "builtin", "history", base["data"]),
            )
    engine.db.execute("UPDATE scans SET status='running'")
    target, home = tmp_path / "history.zip", tmp_path / "history-restored"
    create_backup(engine.db, engine.home, target)
    restore_backup(target, home)
    restored = Engine(home)
    assert restored.db.query("SELECT status FROM scans")[0]["status"] == "interrupted"
    rows = restored.db.query("SELECT data FROM findings UNION ALL SELECT data FROM observations")
    assert len(rows) == 292
    assert all(
        Path(json.loads(row["data"])["evidence"]["snapshot"]).is_relative_to(home) for row in rows
    )


def test_changed_source_during_backup_is_rejected(engine, scanned, tmp_path):
    source = Path(engine.ingestion.project(scanned)["root"]) / "changing.bin"
    source.write_bytes(b"a" * 150_000)
    cancel = Event()

    class MutatingEvent:
        changed = False

        def is_set(self):
            if not self.changed:
                source.write_bytes(b"different")
                self.changed = True
            return cancel.is_set()

    # The public streaming boundary detects another process changing the source mid-copy.
    from oberhau.backup import write_member

    with zipfile.ZipFile(tmp_path / "stream.zip", "w") as archive:
        with pytest.raises(OberhauError, match="changed during backup"):
            write_member(archive, "changing.bin", source, MutatingEvent())
