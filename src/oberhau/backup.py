"""Portable research bundles: SQLite plus every retained managed source snapshot."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import zipfile
from collections.abc import Callable, Iterator
from contextlib import closing
from pathlib import Path, PurePosixPath
from threading import Event

from pydantic import BaseModel, ConfigDict, Field

from oberhau import __version__
from oberhau.core import Cancelled, Finding, OberhauError, now
from oberhau.database import MIGRATIONS, Database
from oberhau.security import confined
from oberhau.storage import store_lock

FORMAT = "oberhau-research-backup"
SCHEMA_QUERY = "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"


class BackupLimits(BaseModel):
    max_files: int = Field(default=100_000, ge=1, le=500_000)
    max_source_bytes: int = Field(default=20_000_000, ge=1)
    max_database_bytes: int = Field(default=1_000_000_000, ge=1)
    max_total_bytes: int = Field(default=4_000_000_000, ge=1)
    max_manifest_bytes: int = Field(default=24_000_000, ge=100)


class Member(BaseModel):
    model_config = ConfigDict(extra="forbid")
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str
    version: int
    application_version: str
    database_schema: int
    created: str
    snapshots: list[str]
    directories: list[str]
    files: dict[str, Member]


def check_cancel(cancel: Event) -> None:
    if cancel.is_set():
        raise Cancelled()


def validate_database(connection: sqlite3.Connection) -> int:
    connection.execute("PRAGMA trusted_schema=OFF")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if not 1 <= version <= len(MIGRATIONS):
        raise OberhauError("Unsupported backup database schema")
    with closing(sqlite3.connect(":memory:")) as expected:
        for migration in MIGRATIONS[:version]:
            expected.executescript(migration)
        if connection.execute(SCHEMA_QUERY).fetchall() != expected.execute(SCHEMA_QUERY).fetchall():
            raise OberhauError(
                "Backup database contains unsupported tables, views, indexes or triggers"
            )
    if (
        connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
        or connection.execute("PRAGMA foreign_key_check").fetchone()
    ):
        raise OberhauError("Backup database integrity check failed")
    return version


def upgrade_database(connection: sqlite3.Connection, version: int) -> None:
    for index in range(version, len(MIGRATIONS)):
        connection.executescript(
            f"BEGIN IMMEDIATE;\n{MIGRATIONS[index]}\nPRAGMA user_version={index + 1};\nCOMMIT;"
        )
    if version < 3:
        connection.execute("DELETE FROM settings WHERE key='advisory_index_version'")
        connection.commit()


def snapshot_reference(value: str, home: Path | None, snapshots: set[str]) -> str:
    if not isinstance(value, str):
        raise OberhauError("Invalid snapshot reference in backup database")
    if home is not None:
        path = Path(value)
        if not path.is_absolute():
            raise OberhauError("Managed snapshot reference must be absolute before backup")
        try:
            value = path.relative_to(home).as_posix()
        except ValueError as error:
            raise OberhauError(
                "Snapshot reference is outside the managed data directory"
            ) from error
    if value not in snapshots:
        raise OberhauError(f"Snapshot referenced by database is missing or unsafe: {value}")
    return value


def database_rows(
    connection: sqlite3.Connection, table: str, columns: str, cancel: Event
) -> Iterator[tuple]:
    last_id = None
    while True:
        check_cancel(cancel)
        if last_id is None:
            rows = connection.execute(
                f"SELECT id,{columns} FROM {table} ORDER BY id LIMIT 128"
            ).fetchall()
        else:
            rows = connection.execute(
                f"SELECT id,{columns} FROM {table} WHERE id>? ORDER BY id LIMIT 128", (last_id,)
            ).fetchall()
        if not rows:
            return
        for row in rows:
            check_cancel(cancel)
            yield row
        last_id = rows[-1][0]


def remap_database(
    connection: sqlite3.Connection,
    snapshots: set[str],
    source_home: Path | None,
    destination_home: Path | None = None,
    cancel: Event | None = None,
) -> None:
    cancel = cancel or Event()

    def remap(value: str) -> str:
        relative = snapshot_reference(value, source_home, snapshots)
        return str(confined(destination_home, relative)) if destination_home else relative

    for project_id, root, metadata_json in database_rows(
        connection, "projects", "root,metadata", cancel
    ):
        metadata = json.loads(metadata_json)
        if not isinstance(metadata, dict):
            raise OberhauError("Malformed project metadata")
        if destination_home:
            metadata["source_link_required"] = True
        if "previous_snapshot" in metadata:
            snapshot_reference(metadata["previous_snapshot"], None, snapshots)
        connection.execute(
            "UPDATE projects SET root=?,metadata=? WHERE id=?",
            (remap(root), json.dumps(metadata), project_id),
        )
    for table in ("findings", "observations"):
        for row_id, payload in database_rows(connection, table, "data", cancel):
            finding = Finding.model_validate_json(payload)
            if "snapshot" not in finding.evidence:
                raise OberhauError("Finding has no managed snapshot reference")
            finding.evidence["snapshot"] = remap(finding.evidence["snapshot"])
            connection.execute(
                f"UPDATE {table} SET data=? WHERE id=?", (finding.model_dump_json(), row_id)
            )
    if destination_home:
        connection.execute("DELETE FROM settings WHERE key='last_diagnostics'")
        connection.execute("INSERT OR REPLACE INTO settings VALUES('schedules_enabled','false')")
        connection.execute("UPDATE schedules SET enabled=0")
        connection.execute(
            "UPDATE scans SET status='interrupted',finished=? WHERE status='running'", (now(),)
        )
        connection.execute(
            "UPDATE scanner_runs SET status='interrupted',finished=? WHERE status IN ('pending','running')",
            (now(),),
        )
        connection.execute(
            "INSERT INTO audit(event,details,created) VALUES(?,?,?)",
            (
                "backup.restore",
                json.dumps({"home": str(destination_home), "schedules_paused": True}),
                now(),
            ),
        )


def snapshot_files(
    home: Path, limits: BackupLimits, cancel: Event
) -> tuple[list[str], list[str], list[tuple[str, Path]]]:
    root = confined(home, "projects")
    snapshots, directories, files = [], [], []
    total = 0
    if not root.exists():
        return snapshots, directories, files
    for entry in sorted(root.iterdir()):
        check_cancel(cancel)
        relative = entry.relative_to(home).as_posix()
        confined(home, relative)
        if not entry.is_dir():
            raise OberhauError("Unexpected non-directory in managed snapshots")
        snapshots.append(relative)
        for directory, dirs, names in os.walk(entry, followlinks=False):
            directories.append(Path(directory).relative_to(home).as_posix())
            if len(directories) + len(files) > limits.max_files:
                raise OberhauError("Retained snapshots exceed backup entry limit")
            dirs.sort()
            for name in dirs:
                confined(home, (Path(directory) / name).relative_to(home).as_posix())
            for name in sorted(names):
                check_cancel(cancel)
                path = Path(directory) / name
                relative = path.relative_to(home).as_posix()
                confined(home, relative)
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > limits.max_source_bytes:
                    raise OberhauError(f"Unsafe or oversized snapshot file: {relative}")
                total += info.st_size
                if (
                    len(files) + len(directories) >= limits.max_files
                    or total > limits.max_total_bytes
                ):
                    raise OberhauError("Retained snapshots exceed backup limits")
                files.append((relative, path))
    names = [*directories, *(relative for relative, _ in files)]
    if len({name.casefold() for name in names}) != len(names):
        raise OberhauError("Snapshot paths collide on Windows")
    return snapshots, directories, files


def write_member(bundle: zipfile.ZipFile, relative: str, path: Path, cancel: Event) -> Member:
    before = path.stat()
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source, bundle.open(relative, "w", force_zip64=True) as target:
        while chunk := source.read(65536):
            check_cancel(cancel)
            digest.update(chunk)
            size += len(chunk)
            target.write(chunk)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or size != before.st_size:
        raise OberhauError(f"File changed during backup: {relative}")
    return Member(size=size, sha256=digest.hexdigest())


def create_backup(
    db: Database,
    home: Path,
    destination: Path,
    cancel: Event | None = None,
    progress: Callable[[str], None] | None = None,
    limits: BackupLimits | None = None,
) -> dict:
    home, destination = home.resolve(), destination.absolute()
    destination = confined(destination.parent.resolve(), destination.name)
    cancel, progress, limits = (
        cancel or Event(),
        progress or (lambda _: None),
        limits or BackupLimits(),
    )
    check_cancel(cancel)
    if (
        destination.exists()
        or destination.is_symlink()
        or destination.is_relative_to(home / "projects")
    ):
        raise OberhauError("Backup destination must be a new file outside managed snapshots")
    if db.path.resolve() != home / "oberhau.sqlite3":
        raise OberhauError("Database and data directory do not match")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        store_lock(home),
        tempfile.TemporaryDirectory(prefix="oberhau-backup-", dir=destination.parent) as temporary,
    ):
        stage = Path(temporary)
        progress("Capturing database and all retained source snapshots")
        snapshots, directories, sources = snapshot_files(home, limits, cancel)
        database = stage / "oberhau.sqlite3"
        with (
            closing(sqlite3.connect(db.path)) as source,
            closing(sqlite3.connect(database)) as target,
        ):
            source.backup(target, pages=128, progress=lambda *_: check_cancel(cancel), sleep=0.05)
        if database.stat().st_size > limits.max_database_bytes:
            raise OberhauError("Database exceeds backup limit")
        with closing(sqlite3.connect(database)) as connection:
            validate_database(connection)
            remap_database(connection, set(snapshots), home, cancel=cancel)
            connection.commit()
            connection.execute("PRAGMA journal_mode=DELETE")
        sources.insert(0, ("oberhau.sqlite3", database))
        members = {}
        archive = stage / "research.oberhau.zip"
        with zipfile.ZipFile(
            archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as bundle:
            total = 0
            for index, (relative, path) in enumerate(sources):
                if relative != "oberhau.sqlite3":
                    confined(home, relative)
                member = write_member(bundle, relative, path, cancel)
                members[relative] = member
                total += member.size
                if total > limits.max_total_bytes:
                    raise OberhauError("Backup exceeds total byte limit")
                if index % 25 == 0:
                    progress(f"Backed up {index + 1}/{len(sources)} files")
            manifest = Manifest(
                format=FORMAT,
                version=1,
                application_version=__version__,
                database_schema=len(MIGRATIONS),
                created=now(),
                snapshots=snapshots,
                directories=directories,
                files=members,
            )
            encoded = manifest.model_dump_json(indent=2).encode("utf-8")
            if len(encoded) > limits.max_manifest_bytes:
                raise OberhauError("Backup manifest exceeds limit")
            bundle.writestr("manifest.json", encoded)
        check_cancel(cancel)
        # Exclusive creation never overwrites an existing backup, including publication races.
        with archive.open("rb") as source:
            target = destination.open("xb")
            try:
                with target:
                    while chunk := source.read(65536):
                        check_cancel(cancel)
                        target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
            except BaseException:
                destination.unlink(missing_ok=True)
                raise
        result = {
            "backup": str(destination),
            "files": len(members),
            "snapshots": len(snapshots),
            "source_bytes": total,
            "archive_bytes": destination.stat().st_size,
        }
        db.audit("backup.complete", result)
        progress("Complete research backup saved")
        return result


def read_manifest(bundle: zipfile.ZipFile, stage: Path, limits: BackupLimits) -> Manifest:
    entries = bundle.infolist()
    if (
        len(entries) > limits.max_files + 2
        or sum(i.file_size for i in entries) > limits.max_total_bytes + limits.max_manifest_bytes
    ):
        raise OberhauError("Backup archive exceeds limits")
    names = set()
    for entry in entries:
        if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise OberhauError("Unsupported backup compression method")
        if PurePosixPath(entry.filename).as_posix() != entry.filename:
            raise OberhauError("Non-canonical backup path")
        confined(stage, entry.filename)
        key = entry.filename.casefold()
        mode = stat.S_IFMT(entry.external_attr >> 16)
        if key in names or entry.is_dir() or mode not in (0, stat.S_IFREG) or entry.flag_bits & 1:
            raise OberhauError("Duplicate, encrypted or unsafe backup entry")
        names.add(key)
        maximum = (
            limits.max_manifest_bytes
            if entry.filename == "manifest.json"
            else limits.max_database_bytes
            if entry.filename == "oberhau.sqlite3"
            else limits.max_source_bytes
        )
        if entry.file_size > maximum:
            raise OberhauError("Backup member exceeds size limit")
    if "manifest.json" not in bundle.namelist():
        raise OberhauError("Backup manifest missing")
    manifest = Manifest.model_validate_json(bundle.read("manifest.json"))
    if (
        manifest.format != FORMAT
        or manifest.version != 1
        or not 1 <= manifest.database_schema <= len(MIGRATIONS)
    ):
        raise OberhauError("Unsupported research backup format or schema")
    if len(manifest.snapshots) > limits.max_files or len(
        set(s.casefold() for s in manifest.snapshots)
    ) != len(manifest.snapshots):
        raise OberhauError("Duplicate or excessive snapshot roots")
    for snapshot in manifest.snapshots:
        if len(Path(snapshot).parts) != 2 or not snapshot.startswith("projects/"):
            raise OberhauError("Unsafe snapshot root")
        confined(stage, snapshot)
    if len(manifest.directories) + len(manifest.files) > limits.max_files + 1 or len(
        set(path.casefold() for path in manifest.directories)
    ) != len(manifest.directories):
        raise OberhauError("Duplicate or excessive backup directories")
    snapshot_set = set(manifest.snapshots)
    if not snapshot_set.issubset(manifest.directories):
        raise OberhauError("Snapshot directories are missing from manifest")
    for directory in manifest.directories:
        if (
            PurePosixPath(directory).as_posix() != directory
            or "/".join(PurePosixPath(directory).parts[:2]) not in snapshot_set
        ):
            raise OberhauError("Unsafe backup directory")
        confined(stage, directory)
    paths = [*manifest.directories, *manifest.files]
    if len({path.casefold() for path in paths}) != len(paths):
        raise OberhauError("File and directory paths collide on Windows")
    directory_set = set(manifest.directories)
    for directory in directory_set - snapshot_set:
        if PurePosixPath(directory).parent.as_posix() not in directory_set:
            raise OberhauError("Backup directory hierarchy is incomplete")
    if (
        set(bundle.namelist()) != {"manifest.json", *manifest.files}
        or "oberhau.sqlite3" not in manifest.files
    ):
        raise OberhauError("Backup entries do not match manifest")
    for relative, member in manifest.files.items():
        parts = PurePosixPath(relative).parts
        if relative != "oberhau.sqlite3" and (
            len(parts) < 3 or "/".join(parts[:2]) not in snapshot_set
        ):
            raise OberhauError("File is outside the declared snapshots")
        if (
            relative != "oberhau.sqlite3"
            and PurePosixPath(relative).parent.as_posix() not in directory_set
        ):
            raise OberhauError("Backup file parent is missing from manifest")
        if bundle.getinfo(relative).file_size != member.size:
            raise OberhauError("Backup file size does not match manifest")
    return manifest


def restore_backup(
    source: Path,
    destination: Path,
    cancel: Event | None = None,
    progress: Callable[[str], None] | None = None,
    limits: BackupLimits | None = None,
) -> dict:
    source, destination = source.absolute(), destination.absolute()
    destination = confined(destination.parent.resolve(), destination.name)
    cancel, progress, limits = (
        cancel or Event(),
        progress or (lambda _: None),
        limits or BackupLimits(),
    )
    check_cancel(cancel)
    if destination.exists() or destination.is_symlink():
        raise OberhauError("Restore destination must be a new data directory")
    if (
        not source.is_file()
        or source.stat().st_size > limits.max_total_bytes + limits.max_manifest_bytes
    ):
        raise OberhauError("Backup is missing or exceeds archive limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="oberhau-restore-", dir=destination.parent
    ) as temporary:
        stage = Path(temporary) / "data"
        stage.mkdir()
        try:
            with zipfile.ZipFile(source) as bundle:
                manifest = read_manifest(bundle, stage, limits)
                required = sum(member.size for member in manifest.files.values())
                if required > limits.max_total_bytes:
                    raise OberhauError("Backup exceeds total byte limit")
                if shutil.disk_usage(stage).free < required + 100_000_000:
                    raise OberhauError("Not enough free disk space to restore research backup")
                for directory in manifest.directories:
                    confined(stage, directory).mkdir(parents=True, exist_ok=True)
                for index, (relative, member) in enumerate(manifest.files.items()):
                    check_cancel(cancel)
                    path = confined(stage, relative)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    digest, size = hashlib.sha256(), 0
                    with bundle.open(relative) as data, path.open("xb") as target:
                        while chunk := data.read(65536):
                            check_cancel(cancel)
                            size += len(chunk)
                            if size > member.size:
                                raise OberhauError("Backup expanded beyond declared size")
                            digest.update(chunk)
                            target.write(chunk)
                    if size != member.size or digest.hexdigest() != member.sha256:
                        raise OberhauError(f"Backup checksum mismatch: {relative}")
                    if index % 25 == 0:
                        progress(f"Restored and verified {index + 1}/{len(manifest.files)} files")
            with closing(sqlite3.connect(stage / "oberhau.sqlite3")) as connection:
                version = validate_database(connection)
                if version != manifest.database_schema:
                    raise OberhauError("Backup database version does not match manifest")
                upgrade_database(connection, version)
                remap_database(connection, set(manifest.snapshots), None, destination, cancel)
                connection.commit()
                connection.execute("PRAGMA journal_mode=DELETE")
            check_cancel(cancel)
            if destination.exists() or destination.is_symlink():
                raise OberhauError("Restore destination was created by another operation")
            stage.rename(destination)
        except (zipfile.BadZipFile, sqlite3.Error, ValueError, KeyError, TypeError) as error:
            raise OberhauError(f"Invalid research backup: {error}") from error
    progress("Research backup restored; schedules paused and original source links require review")
    return {
        "restored": str(destination),
        "files": len(manifest.files),
        "snapshots": len(manifest.snapshots),
        "schedules_paused": True,
        "source_relink_required": True,
    }
