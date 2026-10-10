import hashlib
import io
import json
import sys
import zipfile
from threading import Event

import pytest

from oberhau import tooling
from oberhau.core import Cancelled, Limits, OberhauError
from oberhau.scanners.external import ExternalScanner, parse
from oberhau.security import ProcessRunner


@pytest.fixture
def release(monkeypatch):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("gitleaks.exe", b"synthetic binary fixture; never executed")
        bundle.writestr("../../outside.txt", b"must not be extracted")
    payload = archive.getvalue()
    spec = dict(tooling.PINNED["gitleaks"], sha256=hashlib.sha256(payload).hexdigest())
    monkeypatch.setitem(tooling.PINNED, "gitleaks", spec)
    monkeypatch.setattr(tooling.platform, "system", lambda: "Windows")
    monkeypatch.setattr(tooling.platform, "machine", lambda: "AMD64")

    def fake_download(url, destination, cancel, maximum=300_000_000):
        if cancel.is_set():
            raise Cancelled()
        destination.write_bytes(payload)
        return {"source": url, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}

    monkeypatch.setattr(tooling, "download", fake_download)
    return spec


def test_verified_installation_is_confined_and_detects_tampering(engine, release):
    receipt = tooling.install_tool(engine.home, "gitleaks")
    assert receipt["sha256"] == release["sha256"]
    paths, errors = tooling.managed_tools(engine.home)
    assert "gitleaks" in paths and not errors
    assert not (engine.home.parent / "outside.txt").exists()
    assert tooling.install_tool(engine.home, "gitleaks") == receipt
    binary = tooling.tool_directory(engine.home, "gitleaks") / "gitleaks.exe"
    binary.write_bytes(b"modified")
    paths, errors = tooling.managed_tools(engine.home)
    assert "gitleaks" not in paths and "mismatch" in errors["gitleaks"]
    runner = ProcessRunner(engine.limits, home=engine.home)
    assert "gitleaks" not in runner.tools and "gitleaks" in runner.tool_errors
    with pytest.raises(OberhauError, match="invalid"):
        tooling.install_tool(engine.home, "gitleaks")


def test_wrong_release_checksum_and_cancellation_install_nothing(engine, release, monkeypatch):
    monkeypatch.setitem(tooling.PINNED["gitleaks"], "sha256", "0" * 64)
    with pytest.raises(OberhauError, match="SHA-256 mismatch"):
        tooling.install_tool(engine.home, "gitleaks")
    assert not tooling.tool_directory(engine.home, "gitleaks").exists()
    cancel = Event()
    cancel.set()
    with pytest.raises(Cancelled):
        tooling.install_tool(engine.home, "gitleaks", cancel)
    with pytest.raises(OberhauError, match="Unknown"):
        tooling.install_tool(engine.home, "../untrusted")


def test_osv_feed_refresh_is_explicit_validated_and_detects_corruption(engine, monkeypatch):
    downloaded = []

    def fake_download(url, destination, cancel, maximum=300_000_000):
        downloaded.append(url)
        with zipfile.ZipFile(destination, "w") as bundle:
            bundle.writestr("ADVISORY-EXAMPLE.json", json.dumps({"id": "ADVISORY-EXAMPLE"}))
        return {"source": url, "sha256": tooling.checksum(destination)}

    monkeypatch.setattr(tooling, "download", fake_download)
    receipt = tooling.refresh_osv_cache(engine.home, "PyPI")
    assert receipt["advisories"] == 1 and len(downloaded) == 1
    assert tooling.cache_status(engine.home)["PyPI"]["checksum_valid"]
    (engine.home / "cache/osv/osv-scalibr/PyPI/all.zip").write_bytes(b"corrupt")
    assert not tooling.cache_status(engine.home)["PyPI"]["checksum_valid"]
    adapter = ExternalScanner(
        "osv-scanner", ProcessRunner(engine.limits, {}, engine.home), engine.home
    )
    with pytest.raises(OberhauError, match="cache checksum mismatch"):
        adapter.scan(engine.home, Event())
    assert len(downloaded) == 1  # Scans never call the feed downloader.
    with pytest.raises(OberhauError, match="Supported"):
        tooling.refresh_osv_cache(engine.home, "../PyPI")


def test_failed_osv_refresh_preserves_previous_cache(engine, monkeypatch):
    directory = engine.home / "cache/osv/osv-scalibr/PyPI"
    directory.mkdir(parents=True)
    previous = directory / "all.zip"
    previous.write_bytes(b"previous cache")

    def invalid(url, destination, cancel, maximum=300_000_000):
        with zipfile.ZipFile(destination, "w") as bundle:
            bundle.writestr("advisory.json", "{}")
        return {"sha256": tooling.checksum(destination)}

    monkeypatch.setattr(tooling, "download", invalid)
    with pytest.raises(OberhauError, match="Malformed"):
        tooling.refresh_osv_cache(engine.home, "PyPI")
    assert previous.read_bytes() == b"previous cache"


def test_scanner_environment_ignores_operator_config_and_controls_cache(
    engine, tmp_path, monkeypatch
):
    monkeypatch.setenv("TRIVY_MODULE_DIR", "untrusted modules")
    monkeypatch.setenv("trivy_server", "https://untrusted.invalid")
    monkeypatch.setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "outside cache")
    runner = ProcessRunner(Limits(timeout=10), {"python": sys.executable}, engine.home)
    output = runner.run(
        "python",
        [
            "-c",
            "import os,json; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith(('TRIVY_', 'OSV_SCANNER_'))}))",
        ],
        tmp_path,
        Event(),
    )
    assert json.loads(output) == {
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(engine.home / "cache/osv")
    }


@pytest.mark.parametrize(
    "profile,scanners",
    [("configuration", "misconfig"), ("dependencies", "vuln"), ("deep", "vuln,misconfig")],
)
def test_trivy_profile_uses_offline_controls_and_trusted_configuration(
    engine, profile, scanners, monkeypatch
):
    runner = ProcessRunner(engine.limits, {}, engine.home)
    captured = {}

    def run(tool, args, cwd, cancel, allowed_codes=(0,)):
        captured["args"] = args
        assert (cwd / "trivy.yaml").read_text() == "{}"
        assert (cwd / "ignore").read_text() == ""
        assert list((cwd / "modules").iterdir()) == []
        return '{"SchemaVersion":2,"Results":[]}'

    monkeypatch.setattr(runner, "run", run)
    assert ExternalScanner("trivy", runner, engine.home, profile).scan(engine.home, Event()) == []
    args = captured["args"]
    assert f"--scanners={scanners}" in args
    assert {
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
    }.issubset(args)


def test_osv_fixed_version_evidence_and_trivy_line_numbers(tmp_path):
    data = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "example", "version": "1.0"},
                        "vulnerabilities": [
                            {
                                "id": "TEST-1",
                                "affected": [
                                    {
                                        "ranges": [
                                            {"events": [{"introduced": "0"}, {"fixed": "1.1"}]}
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    finding = parse("osv-scanner", json.dumps(data), tmp_path)[0]
    assert finding.evidence["fixed_versions"] == ["1.1"]
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "TEST-2",
                        "Title": "User",
                        "CauseMetadata": {"StartLine": 2, "EndLine": 4},
                        "Resolution": "Use non-root",
                    }
                ],
            }
        ],
    }
    finding = parse("trivy", json.dumps(data), tmp_path)[0]
    assert (finding.line, finding.end_line) == (2, 4)
    assert finding.evidence["resolution"] == "Use non-root"


@pytest.mark.parametrize(
    "url", ["http://github.com/release", "file:///untrusted", "https://untrusted.invalid/release"]
)
def test_download_rejects_unapproved_sources_before_network(tmp_path, url, monkeypatch):
    monkeypatch.setattr(
        tooling.urllib.request,
        "urlopen",
        lambda *a, **kw: pytest.fail("Network must not be reached"),
    )
    with pytest.raises(OberhauError, match="approved HTTPS"):
        tooling.download(url, tmp_path / "download", Event())


@pytest.mark.parametrize(
    "size,maximum,error", [(6, 20, None), (8, 20, "Incomplete"), (6, 2, "size limit")]
)
def test_download_verifies_length_and_limits_before_installation(
    tmp_path, size, maximum, error, monkeypatch
):
    response = io.BytesIO(b"abcdef")
    response.url = "https://github.com/release"
    response.headers = {"Content-Length": str(size)}
    monkeypatch.setattr(tooling.urllib.request, "urlopen", lambda *a, **kw: response)
    destination = tmp_path / "download"
    if error:
        with pytest.raises(OberhauError, match=error):
            tooling.download(response.url, destination, Event(), maximum)
    else:
        assert (
            tooling.download(response.url, destination, Event(), maximum)["sha256"]
            == hashlib.sha256(b"abcdef").hexdigest()
        )


def test_trivy_refresh_is_a_project_free_download_and_records_metadata(engine, monkeypatch):
    captured = []

    def run(self, tool, args, cwd, cancel, allowed_codes=(0,)):
        captured.extend(args)
        assert tool == "trivy" and "--download-db-only" in args
        assert (cwd / "trivy.yaml").read_text() == "{}"
        directory = engine.home / "cache/trivy/db"
        directory.mkdir(parents=True)
        (directory / "trivy.db").write_bytes(b"synthetic DB; never read by scanner")
        (directory / "metadata.json").write_text(
            '{"Version": 2, "UpdatedAt": "2026-10-10T00:00:00Z"}'
        )
        return ""

    monkeypatch.setattr(ProcessRunner, "run", run)
    receipt = tooling.refresh_trivy_cache(engine.home)
    assert receipt["metadata"]["Version"] == 2
    assert (
        "--offline-scan" not in captured
    )  # This is an explicit public DB refresh, never a project scan.
    assert (
        tooling.cache_status(engine.home)["trivy_vulnerability_db"]["sha256"] == receipt["sha256"]
    )
