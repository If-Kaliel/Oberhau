"""Explicit trusted downloads, separated from offline project scans."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit

from oberhau.core import Cancelled, OberhauError, now
from oberhau.security import confined

PINNED = json.loads((Path(__file__).parent / "assets/tools.json").read_text(encoding="utf-8"))
ECOSYSTEMS = ("PyPI", "npm")


def checksum(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url: str, destination: Path, cancel: Event, maximum: int = 300_000_000) -> dict:
    """Only caller-selected official URLs; bounded transfer with TLS verification."""
    if cancel.is_set():
        raise Cancelled()
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"github.com", "osv-vulnerabilities.storage.googleapis.com"}
        or parsed.username
        or parsed.password
    ):
        raise OberhauError("Download source is not an approved HTTPS release or advisory feed")
    request = urllib.request.Request(url, headers={"User-Agent": "Oberhau/0.1"})
    deadline = time.monotonic() + 300
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if not response.url.startswith("https://"):
                raise OberhauError("Download redirected to an insecure transport")
            expected = response.headers.get("Content-Length")
            if expected and int(expected) > maximum:
                raise OberhauError("Download exceeds size limit")
            size = 0
            with destination.open("xb") as output:
                while chunk := response.read(1_048_576):
                    if cancel.is_set():
                        raise Cancelled()
                    if time.monotonic() > deadline:
                        raise OberhauError("Download timeout")
                    size += len(chunk)
                    if size > maximum:
                        raise OberhauError("Download exceeds size limit")
                    output.write(chunk)
            if cancel.is_set():
                raise Cancelled()
            if expected and size != int(expected):
                raise OberhauError("Incomplete download")
            return {
                "source": url,
                "downloaded": now(),
                "bytes": size,
                "sha256": checksum(destination),
            }
    except (urllib.error.URLError, TimeoutError) as error:
        raise OberhauError(f"Trusted download failed: {error}") from error


def tool_directory(home: Path, tool: str) -> Path:
    if tool not in PINNED:
        raise OberhauError("Unknown managed tool")
    return confined(home, f"tools/{tool}-{PINNED[tool]['version']}")


def install_tool(
    home: Path,
    tool: str,
    cancel: Event | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise OberhauError("Managed binaries currently support Windows x64 only")
    cancel, progress = cancel or Event(), progress or (lambda _: None)
    directory = tool_directory(home, tool)
    spec = PINNED[tool]
    if directory.exists():
        paths, errors = managed_tools(home)
        if tool in paths:
            return json.loads((directory / "receipt.json").read_text(encoding="utf-8"))
        raise OberhauError(
            errors.get(tool, "Tool directory already exists; inspect before replacing")
        )
    work = confined(home, "tmp")
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tool-install-", dir=work) as temporary:
        temp = Path(temporary)
        progress(f"Downloading {tool} {spec['version']} from its official release")
        receipt = download(spec["url"], temp / "download", cancel)
        if receipt["sha256"] != spec["sha256"]:
            raise OberhauError(f"{tool}: release SHA-256 mismatch; nothing installed")
        staged = temp / "staged"
        staged.mkdir()
        binary = staged / spec["executable"]
        if spec["archive"]:
            with zipfile.ZipFile(temp / "download") as archive:
                members = [i for i in archive.infolist() if i.filename == spec["executable"]]
                if len(members) != 1 or members[0].file_size > 250_000_000:
                    raise OberhauError("Release executable missing or oversized")
                # Extract only the exact expected executable, never archive paths or scripts.
                with archive.open(members[0]) as source, binary.open("xb") as target:
                    shutil.copyfileobj(source, target)
        else:
            shutil.copyfile(temp / "download", binary)
        if cancel.is_set():
            raise Cancelled()
        receipt.update(
            {"tool": tool, "version": spec["version"], "binary_sha256": checksum(binary)}
        )
        (staged / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        directory.parent.mkdir(parents=True, exist_ok=True)
        # Rename requires a new destination on Windows and retains the verified receipt with the binary.
        staged.rename(directory)
        progress(f"Installed {tool} locally with a verified release checksum")
        return receipt


def managed_tools(home: Path) -> tuple[dict[str, str], dict[str, str]]:
    paths, errors = {}, {}
    for tool, spec in PINNED.items():
        try:
            directory = tool_directory(home, tool)
            if not directory.exists():
                continue
            receipt_path = confined(home, f"tools/{tool}-{spec['version']}/receipt.json")
            binary = confined(home, f"tools/{tool}-{spec['version']}/{spec['executable']}")
            if receipt_path.stat().st_size > 16_000:
                raise OberhauError("Oversized installation receipt")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if binary.stat().st_size > 250_000_000:
                raise OberhauError("Oversized installed executable")
            if (
                receipt["sha256"] != spec["sha256"]
                or receipt["version"] != spec["version"]
                or receipt["tool"] != tool
                or checksum(binary) != receipt["binary_sha256"]
            ):
                raise OberhauError("Installed tool checksum or receipt mismatch")
            paths[tool] = str(binary)
        except (OSError, ValueError, KeyError, OberhauError) as error:
            errors[tool] = f"{tool}: managed installation invalid: {error}"
    return paths, errors


def refresh_osv_cache(
    home: Path,
    ecosystem: str,
    cancel: Event | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    if ecosystem not in ECOSYSTEMS:
        raise OberhauError("Supported OSV caches: PyPI and npm")
    cancel, progress = cancel or Event(), progress or (lambda _: None)
    directory = confined(home, f"cache/osv/osv-scalibr/{ecosystem}")
    directory.mkdir(parents=True, exist_ok=True)
    url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
    progress(f"Downloading the public OSV {ecosystem} feed; no project information is sent")
    with tempfile.TemporaryDirectory(prefix="osv-refresh-", dir=directory.parent) as temporary:
        archive_path = Path(temporary) / "all.zip"
        receipt = download(url, archive_path, cancel)
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if (
                not members
                or len(members) > 100_000
                or sum(i.file_size for i in members) > 1_000_000_000
                or any(
                    i.file_size > 10_000_000 or not i.filename.endswith(".json") for i in members
                )
            ):
                raise OberhauError("Unsupported or oversized OSV feed archive")
            # The scanner reads JSON directly from ZIP; no files are extracted or executed.
            for member in members:
                if cancel.is_set():
                    raise Cancelled()
                advisory = json.loads(archive.read(member))
                if not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str):
                    raise OberhauError("Malformed OSV advisory in feed")
        receipt.update({"ecosystem": ecosystem, "advisories": len(members)})
        staged_receipt = Path(temporary) / "receipt.json"
        staged_receipt.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        if cancel.is_set():
            raise Cancelled()
        archive_path.replace(directory / "all.zip")
        staged_receipt.replace(directory / "receipt.json")
    progress(f"OSV {ecosystem} cache refreshed: {len(members)} advisories")
    return receipt


def cache_status(home: Path) -> dict:
    result = {}
    for ecosystem in ECOSYSTEMS:
        directory = confined(home, f"cache/osv/osv-scalibr/{ecosystem}")
        try:
            receipt = json.loads((directory / "receipt.json").read_text(encoding="utf-8"))
            present = (directory / "all.zip").is_file()
            result[ecosystem] = {
                **receipt,
                "present": present,
                "checksum_valid": present
                and checksum(directory / "all.zip") == receipt.get("sha256"),
            }
        except (OSError, ValueError):
            result[ecosystem] = {"present": False}
    result["trivy_vulnerability_db"] = {
        "present": (home / "cache/trivy/db/trivy.db").is_file(),
        "instructions": "Use a trusted Trivy database download into this cache before dependency scans.",
    }
    try:
        result["trivy_vulnerability_db"].update(
            json.loads((home / "cache/trivy/db/receipt.json").read_text(encoding="utf-8"))
        )
    except (OSError, ValueError):
        pass
    return result


def refresh_trivy_cache(
    home: Path, cancel: Event | None = None, progress: Callable[[str], None] | None = None
) -> dict:
    """Download Trivy's advisory DB explicitly, without a project argument."""
    from oberhau.core import Limits
    from oberhau.security import ProcessRunner

    cancel, progress = cancel or Event(), progress or (lambda _: None)
    runner = ProcessRunner(Limits(timeout=300), home=home)
    cache = confined(home, "cache/trivy")
    work = confined(home, "tmp")
    work.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(home).free < 4_000_000_000:
        raise OberhauError("Trivy database refresh requires at least 4 GB of free disk space")
    progress("Downloading the public Trivy vulnerability database; no project information is sent")
    with tempfile.TemporaryDirectory(prefix="trivy-refresh-", dir=work) as temporary:
        temp = Path(temporary)
        config = temp / "trivy.yaml"
        config.write_text("{}", encoding="utf-8")
        runner.run(
            "trivy",
            [
                "fs",
                "--download-db-only",
                "--cache-dir",
                str(cache),
                "--config",
                str(config),
                "--skip-version-check",
                "--disable-telemetry",
                "--timeout=300s",
            ],
            temp,
            cancel,
        )
    binary = confined(home, "cache/trivy/db/trivy.db")
    metadata = json.loads(
        confined(home, "cache/trivy/db/metadata.json").read_text(encoding="utf-8")
    )
    if metadata.get("Version") != 2 or not 0 < binary.stat().st_size <= 2_000_000_000:
        raise OberhauError("Unsupported or oversized Trivy database")
    receipt = {
        "downloaded": now(),
        "sha256": checksum(binary),
        "bytes": binary.stat().st_size,
        "metadata": metadata,
    }
    (binary.parent / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    progress("Trivy vulnerability database refreshed")
    return receipt
