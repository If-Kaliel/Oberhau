"""Opt-in execution of real, preinstalled scanners on generated local fixtures."""

import os
from pathlib import Path
from threading import Event

import pytest

from oberhau.core import Limits
from oberhau.engine import ASSETS
from oberhau.scanners.external import ExternalScanner
from oberhau.security import ProcessRunner

pytestmark = pytest.mark.skipif(
    not os.environ.get("OBERHAU_INTEGRATION_HOME"),
    reason="Set OBERHAU_INTEGRATION_HOME after explicit scanner/cache setup",
)


@pytest.fixture
def scanner():
    home = Path(os.environ["OBERHAU_INTEGRATION_HOME"]).resolve()
    runner = ProcessRunner(Limits(timeout=120), home=home)

    def create(tool, profile="deep"):
        assert tool in runner.tools, f"Install {tool} in OBERHAU_INTEGRATION_HOME before this test"
        return ExternalScanner(tool, runner, ASSETS / "rules.yaml", profile)

    return create


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "projects/fixture"
    root.mkdir(parents=True)
    return root


def test_live_gitleaks_detection_redaction_and_corrected_control(scanner, source):
    # Deterministic fabricated token matches the scanner's syntax; never authenticates anywhere.
    credential = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    (source / "settings.py").write_text(f'github_token = "{credential}"\n', encoding="utf-8")
    findings = scanner("gitleaks").scan(source, Event())
    assert any(f.rule == "github-pat" for f in findings)
    assert all(f.evidence["scanner_provenance"]["managed_version"] == "8.30.1" for f in findings)
    assert credential not in "".join(f.model_dump_json() for f in findings)
    (source / "settings.py").write_text("github_token = None\n", encoding="utf-8")
    assert scanner("gitleaks").scan(source, Event()) == []


def test_live_osv_matching_fixed_versions_and_corrected_control(scanner, source):
    requirements = source / "requirements.txt"
    requirements.write_text("Django==2.2.0\n", encoding="utf-8")
    findings = scanner("osv-scanner", "dependencies").scan(source, Event())
    assert findings and all(f.category == "dependencies" for f in findings)
    assert any(f.evidence["fixed_versions"] for f in findings)
    assert all(
        f.evidence["scanner_provenance"]["advisory_caches"]["PyPI"]["sha256"] for f in findings
    )
    assert all(f.path == "requirements.txt" for f in findings)
    # Current patched release verified against the official Django download page on 2026-10-10.
    # This is an advisory-negative control for this feed snapshot, never a proof of general safety.
    requirements.write_text("Django==6.1.2\n", encoding="utf-8")
    assert scanner("osv-scanner", "dependencies").scan(source, Event()) == []


def test_live_trivy_configuration_lines_and_corrected_control(scanner, source):
    dockerfile = source / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\nUSER root\n", encoding="utf-8")
    findings = scanner("trivy", "configuration").scan(source, Event())
    root_findings = [f for f in findings if f.line == 2 and "root" in f.explanation.lower()]
    assert root_findings
    dockerfile.write_text("FROM python:3.12-slim\nUSER app\n", encoding="utf-8")
    corrected = scanner("trivy", "configuration").scan(source, Event())
    assert not any(f.rule in {f.rule for f in root_findings} for f in corrected)


def test_live_trivy_dependency_advisory_and_corrected_control(scanner, source):
    requirements = source / "requirements.txt"
    requirements.write_text("Django==2.2.0\n", encoding="utf-8")
    findings = scanner("trivy", "dependencies").scan(source, Event())
    assert findings and any(f.evidence.get("fixed") for f in findings)
    assert all(f.path == "requirements.txt" for f in findings)
    requirements.write_text("Django==6.1.2\n", encoding="utf-8")
    assert scanner("trivy", "dependencies").scan(source, Event()) == []
