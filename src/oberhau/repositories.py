"""Explicit public HTTPS Git snapshots: isolated configuration, verified raw blobs, bounded staging."""

from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import tempfile
import time
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from threading import Event
from urllib.parse import urlsplit

from oberhau.core import Cancelled, OberhauError, now
from oberhau.ingestion import Ingestion
from oberhau.security import ProcessRunner, confined, enforce_disk_limit
from oberhau.storage import storage_operation

HOSTS = {"github.com", "gitlab.com", "codeberg.org"}
GIT_OPTIONS = [
    "-c",
    "core.hooksPath=",
    "-c",
    "core.attributesFile=",
    "-c",
    "credential.helper=",
    "-c",
    "credential.interactive=false",
    "-c",
    "core.askPass=",
    "-c",
    "core.longpaths=true",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "http.followRedirects=false",
    "-c",
    "http.sslVerify=true",
    "-c",
    "http.extraHeader=",
    "-c",
    "http.proxy=",
    "-c",
    "fetch.fsckObjects=true",
    "-c",
    "transfer.fsckObjects=true",
    "-c",
    "submodule.recurse=false",
    "-c",
    "maintenance.auto=false",
    "-c",
    "gc.auto=0",
    "-c",
    "promisor.acceptFromServer=none",
]


def repository_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise OberhauError("Invalid repository URL") from error
    parts = parsed.path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.hostname not in HOSTS
        or port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or value != value.strip()
        or not 2 <= len(parts) <= 8
    ):
        raise OberhauError(
            "Use a public HTTPS GitHub, GitLab or Codeberg repository URL without credentials or query parameters"
        )
    if parsed.hostname != "gitlab.com" and len(parts) != 2:
        raise OberhauError("Use the repository URL, without tree/blob or other page paths")
    if any(
        part in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part)
        for part in parts
    ):
        raise OberhauError("Invalid repository path")
    return f"https://{parsed.hostname}/" + "/".join(parts).removesuffix(".git") + ".git"


def repository_ref(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", value)
        or ".." in value
        or "//" in value
        or value.endswith(("/", ".", ".lock"))
        or any(part.startswith(".") for part in value.split("/"))
    ):
        raise OberhauError("Invalid Git branch or tag name")
    return value


def change_summary(before: dict[str, str], after: dict[str, str]) -> dict:
    added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
    modified = sorted(path for path in set(before) & set(after) if before[path] != after[path])
    return {
        "added": added[:1000],
        "removed": removed[:1000],
        "modified": modified[:1000],
        "counts": {"added": len(added), "removed": len(removed), "modified": len(modified)},
        "truncated": max(len(added), len(removed), len(modified)) > 1000,
    }


class GitRepositories:
    def __init__(self, ingestion: Ingestion):
        self.ingestion, self.home, self.db, self.limits = (
            ingestion,
            ingestion.home,
            ingestion.db,
            ingestion.limits,
        )

    @storage_operation
    def add(
        self,
        url: str,
        name: str,
        program_id: int | None = None,
        ref: str | None = None,
        cancel: Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> int:
        url, ref = repository_url(url), repository_ref(ref)
        cancel, progress = cancel or Event(), progress or (lambda _: None)
        if cancel.is_set():
            raise Cancelled()
        if not name.strip():
            raise OberhauError("Project name is required")
        binary = shutil.which("git")
        if not binary:
            raise OberhauError("Git is not installed")
        work = confined(self.home, "tmp")
        work.mkdir(exist_ok=True)
        if (
            shutil.disk_usage(work).free
            < self.limits.max_git_bytes + self.limits.max_total_bytes + 100_000_000
        ):
            raise OberhauError("Insufficient free disk for bounded Git staging and source snapshot")
        deadline = time.monotonic() + self.limits.timeout
        with tempfile.TemporaryDirectory(prefix="oberhau-git-", dir=work) as temporary:
            stage = Path(temporary)
            repo, profile, template, source = (
                stage / "repository",
                stage / "profile",
                stage / "template",
                stage / "source",
            )
            for folder in (profile, template, source):
                folder.mkdir()
            (profile / "empty.config").write_text("", encoding="utf-8")
            runner = ProcessRunner(self.limits, {"git": binary}, git_home=profile)

            def run(args, cwd=stage, **kwargs):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OberhauError("Git import exceeded configured timeout")
                runner.limits = self.limits.model_copy(
                    update={"timeout": max(1, math.ceil(remaining))}
                )
                return runner.run(
                    "git",
                    [*GIT_OPTIONS, *args],
                    cwd,
                    cancel,
                    disk_root=stage,
                    max_disk_bytes=self.limits.max_git_bytes,
                    **kwargs,
                )

            progress(
                "Downloading explicit public Git source; hooks, credentials and submodules are disabled"
            )
            args = [
                "clone",
                "--no-checkout",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                f"--template={template}",
            ]
            if ref:
                args.extend(["--branch", ref])
            args.extend(["--", url, str(repo)])
            run(args)
            commit = run(["rev-parse", "--verify", "HEAD^{commit}"], repo).strip()
            if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
                raise OberhauError("Git did not provide a valid commit identifier")
            entries = self.validate_tree(run(["ls-tree", "-r", "-l", "-z", "HEAD"], repo), source)
            blobs = stage / "blobs.bin"
            progress(
                f"Extracting {len(entries)} verified raw blobs at commit {commit[:12]}; checkout filters are never invoked"
            )
            requests = "".join(f"{oid}\n" for _, oid, _ in entries).encode("ascii")
            run(
                ["cat-file", "--batch"],
                repo,
                stdin_data=requests,
                stdout_path=blobs,
                output_limit=sum(size for _, _, size in entries) + len(entries) * 150 + 1000,
            )
            lfs = []
            with blobs.open("rb") as data:
                for index, (relative, oid, size) in enumerate(entries):
                    if cancel.is_set():
                        raise Cancelled()
                    if time.monotonic() > deadline:
                        raise OberhauError("Git import exceeded configured timeout")
                    header = data.readline(200).decode("ascii").strip().split()
                    if header != [oid, "blob", str(size)]:
                        raise OberhauError("Git raw blob stream does not match tree")
                    content = data.read(size)
                    digest = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
                    if (
                        data.read(1) != b"\n"
                        or len(content) != size
                        or digest(f"blob {size}\0".encode() + content).hexdigest() != oid
                    ):
                        raise OberhauError("Git blob integrity verification failed")
                    target = confined(source, relative)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as output:
                        output.write(content)
                    if content.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                        lfs.append(relative)
                    if index % 25 == 0:
                        enforce_disk_limit(stage, self.limits.max_git_bytes)
                        progress(f"Verified {index + 1}/{len(entries)} Git source files")
                if data.read(1):
                    raise OberhauError("Unexpected bytes after Git blob stream")
            version = run(["--version"]).strip()
            project = self.ingestion.add(source, name, program_id, cancel=cancel)
            try:
                row = self.ingestion.project(project)
                metadata = json.loads(row["metadata"])
                included = set(metadata["manifest"])
                excluded = sorted(
                    relative for relative, _, _ in entries if relative not in included
                )
                metadata.update(
                    {
                        "source_kind": "git",
                        "repository_url": url,
                        "ref": ref,
                        "commit": commit,
                        "imported": now(),
                        "git_version": version,
                        "source_link_required": False,
                        "git_tree_files": len(entries),
                        "excluded_files": excluded[:1000],
                        "excluded_count": len(excluded),
                        "lfs_pointers": lfs[:1000],
                        "lfs_pointer_count": len(lfs),
                        "limitations": [
                            "Shallow committed snapshot; Git history excluded",
                            "Submodules and symlinks rejected",
                            "Git LFS pointers are not downloaded",
                            "Generated directories follow the ingestion exclusion policy",
                        ],
                    }
                )
                self.db.execute(
                    "UPDATE projects SET origin=?,metadata=? WHERE id=?",
                    (url, json.dumps(metadata), project),
                )
                self.db.audit(
                    "repository.import",
                    {
                        "project": project,
                        "url": url,
                        "ref": ref,
                        "commit": commit,
                        "excluded": len(excluded),
                        "lfs_pointers": len(lfs),
                    },
                )
            except BaseException:
                self.db.execute("DELETE FROM projects WHERE id=?", (project,))
                raise
        progress(f"Imported Git snapshot {commit[:12]}; project #{project}")
        return project

    def validate_tree(self, payload: str, root: Path) -> list[tuple[str, str, int]]:
        entries, names, files, total = [], {}, set(), 0
        for record in payload.split("\0"):
            if not record:
                continue
            header, separator, relative = record.partition("\t")
            columns = header.split()
            if not separator or len(columns) != 4:
                raise OberhauError("Unsupported Git tree listing")
            mode, kind, oid, size = columns
            if mode not in {"100644", "100755"} or kind != "blob":
                raise OberhauError(
                    "Git source contains symlinks or submodules; import a reviewed local source instead"
                )
            if PurePosixPath(relative).as_posix() != relative or "\ufffd" in relative:
                raise OberhauError("Unsupported Git filename")
            confined(root, relative)
            parts = PurePosixPath(relative).parts
            key = relative.casefold()
            if key in names or any(
                "/".join(parts[:i]).casefold() in files for i in range(1, len(parts))
            ):
                raise OberhauError("Duplicate or structurally conflicting Git path")
            if any(part.lower() == ".git" for part in parts):
                raise OberhauError("Git metadata path is not valid imported source")
            for index in range(1, len(parts) + 1):
                prefix = "/".join(parts[:index])
                key = prefix.casefold()
                if key in names and names[key] != prefix:
                    raise OberhauError("Git paths collide on Windows")
                names[key] = prefix
            files.add(relative.casefold())
            try:
                amount = int(size)
            except ValueError as error:
                raise OberhauError("Invalid Git blob size") from error
            if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", oid):
                raise OberhauError("Invalid Git blob identifier")
            if amount < 0 or amount > self.limits.max_file_bytes:
                raise OberhauError("Git source file exceeds configured size limit")
            total += amount
            if len(entries) >= self.limits.max_files or total > self.limits.max_total_bytes:
                raise OberhauError("Git tree exceeds configured source limits")
            entries.append((relative, oid, amount))
        return entries

    @storage_operation
    def refresh(
        self,
        project_id: int,
        cancel: Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        row = self.ingestion.project(project_id)
        old = json.loads(row["metadata"])
        if old.get("source_link_required"):
            raise OberhauError(
                "Restored repository URL must be explicitly relinked before refreshing"
            )
        if old.get("source_kind") != "git":
            raise OberhauError("Project is not a remote Git snapshot")
        replacement = self.add(
            row["origin"], row["name"], row["program_id"], old.get("ref"), cancel, progress
        )
        fresh = self.ingestion.project(replacement)
        metadata = json.loads(fresh["metadata"])
        metadata.update(
            {
                "previous_snapshot": Path(row["root"]).relative_to(self.home).as_posix(),
                "previous_commit": old.get("commit"),
                "previous_manifest": old["manifest"],
                "changes": change_summary(old["manifest"], metadata["manifest"]),
            }
        )
        with self.db.connect() as connection:
            connection.execute("DELETE FROM projects WHERE id=?", (replacement,))
            connection.execute(
                "UPDATE projects SET root=?,metadata=? WHERE id=?",
                (fresh["root"], json.dumps(metadata), project_id),
            )
        self.db.audit(
            "repository.refresh",
            {
                "project": project_id,
                "before": old.get("commit"),
                "after": metadata["commit"],
                "changes": metadata["changes"]["counts"],
            },
        )

    @storage_operation
    def relink(self, project_id: int, url: str, ref: str | None = None) -> None:
        row = self.ingestion.project(project_id)
        metadata = json.loads(row["metadata"])
        url, ref = repository_url(url), repository_ref(ref)
        metadata.update(
            {"source_kind": "git", "repository_url": url, "ref": ref, "source_link_required": False}
        )
        self.db.execute(
            "UPDATE projects SET origin=?,metadata=? WHERE id=?",
            (url, json.dumps(metadata), project_id),
        )
        self.db.audit("repository.relink", {"project": project_id, "url": url, "ref": ref})
