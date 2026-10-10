from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path
from threading import Event

from oberhau.core import Cancelled, Limits, OberhauError, now
from oberhau.database import Database
from oberhau.security import ProcessRunner, confined
from oberhau.storage import storage_operation

EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".oberhau",
    ".idea",
}
LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "React",
    ".ts": "TypeScript",
    ".tsx": "React",
    ".java": "Java",
    ".cs": "C#",
    ".sql": "SQL",
    ".tf": "Terraform",
}


def file_index(root: Path, limits: Limits, cancel: Event) -> dict[str, str]:
    result: dict[str, str] = {}
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in EXCLUDED
            and not (Path(directory) / d).is_symlink()
            and not (Path(directory) / d).is_junction()
        )
        for name in sorted(files):
            if cancel.is_set():
                raise Cancelled()
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            confined(root, relative)
            size = path.stat().st_size
            if size > limits.max_file_bytes:
                raise OberhauError(f"File exceeds configured limit: {relative}")
            total += size
            if len(result) >= limits.max_files or total > limits.max_total_bytes:
                raise OberhauError("Project exceeds configured file or byte limit")
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def safe_extract(
    archive: Path, destination: Path, limits: Limits, cancel: Event | None = None
) -> None:
    cancel = cancel or Event()
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if (
            len(entries) > limits.max_files
            or sum(e.file_size for e in entries) > limits.max_total_bytes
        ):
            raise OberhauError("Archive exceeds configured limits")
        seen: set[str] = set()
        for entry in entries:
            if cancel.is_set():
                raise Cancelled()
            name = entry.filename.rstrip("/")
            if not name:
                continue
            key = name.casefold()
            if key in seen:
                raise OberhauError("Duplicate archive path")
            seen.add(key)
            path = confined(destination, name)
            if any(part in EXCLUDED for part in Path(name).parts):
                continue
            if stat.S_ISLNK(entry.external_attr >> 16) or entry.file_size > limits.max_file_bytes:
                raise OberhauError("Unsafe archive entry")
            if entry.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(entry) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target, 65536)


class Ingestion:
    def __init__(self, db: Database, home: Path, limits: Limits):
        self.db, self.home, self.limits = db, home, limits
        (home / "projects").mkdir(parents=True, exist_ok=True)

    @storage_operation
    def add(
        self,
        source: Path,
        name: str,
        program_id: int | None = None,
        demo: bool = False,
        cancel: Event | None = None,
    ) -> int:
        cancel = cancel or Event()
        if cancel.is_set():
            raise Cancelled()
        source = source.absolute()
        if not source.exists() or source.is_symlink() or source.is_junction():
            raise OberhauError(
                "Source must be an existing local directory, file, or ZIP without links"
            )
        if not name.strip():
            raise OberhauError("Project name is required")
        if source.is_dir() and self.home.resolve().is_relative_to(source.resolve()):
            raise OberhauError("Source contains Oberhau storage; choose a separate data directory")
        root = Path(tempfile.mkdtemp(prefix="project-", dir=self.home / "projects"))
        try:
            commit_hash = None
            if source.is_dir():
                manifest = file_index(source, self.limits, cancel)
                for relative in manifest:
                    if cancel.is_set():
                        raise Cancelled()
                    target = confined(root, relative)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(confined(source, relative), target)
                if (source / ".git").exists() and shutil.which("git"):
                    commit_hash = (
                        ProcessRunner(self.limits)
                        .run(
                            "git",
                            ["-c", "core.hooksPath=NUL", "rev-parse", "HEAD"],
                            source,
                            cancel,
                        )
                        .strip()
                    )
            elif source.suffix.lower() == ".zip":
                safe_extract(source, root, self.limits, cancel)
            else:
                if source.stat().st_size > self.limits.max_file_bytes:
                    raise OberhauError("Source file exceeds configured limit")
                shutil.copyfile(source, confined(root, source.name))
            manifest = file_index(root, self.limits, cancel)
            languages = sorted(
                {LANGUAGES[Path(p).suffix] for p in manifest if Path(p).suffix in LANGUAGES}
            )
            metadata = {
                "manifest": manifest,
                "languages": languages,
                "commit": commit_hash,
                "manifests": [
                    p
                    for p in manifest
                    if Path(p).name
                    in {
                        "package-lock.json",
                        "requirements.txt",
                        "pyproject.toml",
                        "pom.xml",
                        "go.sum",
                        "Cargo.lock",
                    }
                ],
            }
            project_id = self.db.execute(
                "INSERT INTO projects(name,root,origin,program_id,metadata,demo,created) VALUES(?,?,?,?,?,?,?)",
                (
                    name.strip(),
                    str(root),
                    str(source),
                    program_id,
                    json.dumps(metadata),
                    int(demo),
                    now(),
                ),
            )
            self.db.audit(
                "project.import", {"id": project_id, "source": str(source), "files": len(manifest)}
            )
            return project_id
        except BaseException:
            shutil.rmtree(root)
            raise

    def project(self, project_id: int) -> dict:
        rows = self.db.query("SELECT * FROM projects WHERE id=?", (project_id,))
        if not rows:
            raise OberhauError("Project does not exist")
        return rows[0]

    @storage_operation
    def refresh(self, project_id: int, cancel: Event | None = None) -> None:
        project = self.project(project_id)
        if json.loads(project["metadata"]).get("source_kind") == "git":
            raise OberhauError("Use the shared engine refresh for remote Git snapshots")
        if json.loads(project["metadata"]).get("source_link_required"):
            raise OberhauError("Restored source must be relinked explicitly before refreshing")
        source = Path(project["origin"])
        if source.suffix.lower() == ".zip" or not source.exists():
            raise OberhauError(
                "Refresh supports existing local directories and source files; reimport archives separately"
            )
        replacement = self.add(
            source, project["name"], project["program_id"], bool(project["demo"]), cancel
        )
        fresh = self.project(replacement)
        from oberhau.repositories import change_summary

        old_metadata, metadata = json.loads(project["metadata"]), json.loads(fresh["metadata"])
        metadata.update(
            {
                "previous_snapshot": Path(project["root"]).relative_to(self.home).as_posix(),
                "previous_commit": old_metadata.get("commit"),
                "previous_manifest": old_metadata["manifest"],
                "changes": change_summary(old_metadata["manifest"], metadata["manifest"]),
            }
        )
        # Keep identity and history; snapshots are swapped only after a complete import.
        with self.db.connect() as connection:
            connection.execute("DELETE FROM projects WHERE id=?", (replacement,))
            connection.execute(
                "UPDATE projects SET root=?,metadata=? WHERE id=?",
                (fresh["root"], json.dumps(metadata), project_id),
            )
        self.db.audit("project.refresh", {"id": project_id})
        # Old immutable snapshots remain for evidence and can be removed after retention review.

    @storage_operation
    def relink(self, project_id: int, source: Path) -> None:
        project = self.project(project_id)
        source = source.absolute()
        if (
            not source.exists()
            or source.is_symlink()
            or source.is_junction()
            or source.suffix.lower() == ".zip"
        ):
            raise OberhauError(
                "Relink to an existing local folder or source file without links; reimport ZIPs separately"
            )
        if source.is_dir() and self.home.resolve().is_relative_to(source.resolve()):
            raise OberhauError("Source contains Oberhau storage")
        metadata = json.loads(project["metadata"])
        metadata["source_link_required"] = False
        metadata["source_kind"] = "local"
        self.db.execute(
            "UPDATE projects SET origin=?,metadata=? WHERE id=?",
            (str(source), json.dumps(metadata), project_id),
        )
        self.db.audit("project.relink", {"id": project_id, "source": str(source)})
