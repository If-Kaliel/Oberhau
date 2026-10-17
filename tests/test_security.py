import json
import sqlite3
import sys
import zipfile
from threading import Event, Timer

import pytest

from oberhau.core import Cancelled, Limits, OberhauError
from oberhau.ingestion import safe_extract
from oberhau.scope import Policy, block_active
from oberhau.security import (
    ProcessRunner,
    confined,
    local_ollama_url,
    redact,
    redact_source,
    sanitize,
    source_lines,
    split_source,
)


@pytest.mark.parametrize(
    "path", ["../escape", "/absolute", "C:/escape", "a\\b", "NUL", "con.txt", "file.", "a/../../b"]
)
def test_path_confinement(tmp_path, path):
    with pytest.raises(OberhauError):
        confined(tmp_path, path)


@pytest.mark.parametrize(
    "name", ["../escape", "C:/evil", "dir\\..\\escape", "NUL", "a/../../escape"]
)
def test_archive_traversal(tmp_path, name):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(name, "bad")
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(OberhauError):
        safe_extract(archive, target, Limits())


def test_archive_symlink_and_size(tmp_path):
    archive = tmp_path / "bad.zip"
    entry = zipfile.ZipInfo("link")
    entry.external_attr = 0o120777 << 16
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(entry, "../outside")
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(OberhauError):
        safe_extract(archive, target, Limits())
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("large.txt", "x" * 200)
    with pytest.raises(OberhauError):
        safe_extract(archive, target, Limits(max_file_bytes=100))


def test_valid_zip_and_single_file_import(engine, tmp_path):
    archive = tmp_path / "good.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("src/control.py", "print('safe')")
    project = engine.ingestion.add(archive, "Archive")
    engine.scan(project, "quick")
    assert not engine.db.query("SELECT * FROM findings")


def test_import_inaccessible_and_invalid_archive(engine, tmp_path):
    with pytest.raises(OberhauError):
        engine.ingestion.add(tmp_path / "missing", "Missing")
    archive = tmp_path / "invalid.zip"
    archive.write_text("invalid")
    with pytest.raises(zipfile.BadZipFile):
        engine.ingestion.add(archive, "Invalid")
    assert not list((engine.home / "projects").iterdir())


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://127.0.0.1.evil.test",
        "http://user:pass@localhost",
        "http://localhost/path",
        "file:///tmp/model",
        "http://localhost?url=remote",
    ],
)
def test_ollama_cannot_use_external_endpoint(url):
    with pytest.raises(OberhauError):
        local_ollama_url(url)


def test_scope_fail_closed():
    policy = Policy(
        allowed_hosts=["example.com"],
        excluded_hosts=["excluded.example.com"],
        reviewed=True,
        automation_allowed=True,
        allowed_categories=["headers"],
    )
    policy.authorize("https://example.com", "headers", 1, True)
    for url, category, revision, approved in [
        ("https://evil.test", "headers", 1, True),
        ("https://example.com.evil.test", "headers", 1, True),
        ("https://example.com", "intrusive", 1, True),
        ("https://example.com", "headers", 2, True),
        ("https://example.com", "headers", 1, False),
        ("https://excluded.example.com", "headers", 1, True),
    ]:
        with pytest.raises(OberhauError):
            policy.authorize(url, category, revision, approved)
    with pytest.raises(OberhauError):
        block_active()
    with pytest.raises(ValueError):
        Policy(allowed_hosts=["*.example.com"])


def test_redaction_preserves_json_structure():
    secret = "sensitive_demo_password_123"
    value = {
        "context": f'password = "{secret}"',
        "secret": secret,
        "nested": [f'"token": "{secret}"'],
    }
    serialized = json.dumps(sanitize(value))
    assert secret not in serialized
    json.loads(serialized)
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in redact(
        "ghp_abcdefghijklmnopqrstuvwxyz123456"
    )


def test_private_key_excerpts_preserve_lines_and_withhold_material():
    source = "prefix\n-----BEGIN PRIVATE KEY-----\nprivatebody1\nprivatebody2\n-----END PRIVATE KEY-----\nsuffix"
    redacted = redact_source(source)
    assert len(source.splitlines()) == len(redacted.splitlines())
    assert "privatebody" not in redacted


@pytest.mark.parametrize(
    ("source", "python", "expected"),
    [
        ('a = " \x85"\nb\n', False, ['a = " \x85"', "b"]),
        ("a\r\nb\r\n", False, ["a", "b"]),
        ("a\rb\rc", True, ["a", "b", "c"]),
        ("a\rb\nc", False, ["ab", "c"]),
        ("", False, []),
    ],
)
def test_source_lines_follow_parser_line_numbering(source, python, expected):
    assert source_lines(source, python) == expected
    assert len(split_source(source, python)) == len(expected)


def test_source_lines_redact_private_keys_without_moving_lines():
    source = "a\n-----BEGIN PRIVATE KEY-----\rbody\r\n-----END PRIVATE KEY-----\nlast"
    lines = source_lines(source)
    assert len(lines) == len(split_source(source)) == 4
    assert lines[-1] == "last" and "body" not in "".join(lines)


def test_builtin_line_numbers_ignore_unicode_separators(engine, tmp_path):
    source = tmp_path / "settings.py"
    source.write_text('LABEL = "a b"\nDEBUG = True\n', encoding="utf-8")
    engine.scan(engine.ingestion.add(source, "Separators"), "quick")
    row = engine.db.query("SELECT id FROM findings")[0]
    assert engine.db.finding(row["id"])["finding"].line == 2
    assert "    2  DEBUG = True" in engine.investigate(row["id"])["context"]


def test_process_allowlist_and_no_shell(tmp_path):
    runner = ProcessRunner(Limits(timeout=3), {"git": sys.executable})
    assert (
        runner.run("git", ["-c", "print('literal ; not a shell')"], tmp_path, Event()).strip()
        == "literal ; not a shell"
    )
    with pytest.raises(OberhauError, match="not installed"):
        runner.run("unknown", [], tmp_path, Event())
    with pytest.raises(OberhauError, match="Invalid"):
        runner.run("git", ["bad\0arg"], tmp_path, Event())


def test_process_timeout_and_cancellation(tmp_path):
    runner = ProcessRunner(Limits(timeout=1), {"git": sys.executable})
    with pytest.raises(OberhauError, match="timeout"):
        runner.run("git", ["-c", "import time; time.sleep(20)"], tmp_path, Event())
    cancel = Event()
    timer = Timer(0.2, cancel.set)
    timer.start()
    with pytest.raises(Cancelled):
        runner.run("git", ["-c", "import time; time.sleep(20)"], tmp_path, cancel)
    timer.join()


def test_output_limit_and_nonzero_exit(tmp_path):
    runner = ProcessRunner(Limits(max_output_bytes=1000), {"git": sys.executable})
    with pytest.raises(OberhauError, match="output limit"):
        runner.run("git", ["-c", "print('x'*10000)"], tmp_path, Event())
    with pytest.raises(OberhauError, match="exit 9"):
        runner.run("git", ["-c", "raise SystemExit(9)"], tmp_path, Event())


def test_backup_future_version_rejected(tmp_path):
    source = tmp_path / "future.sqlite3"
    with sqlite3.connect(source) as db:
        db.execute("PRAGMA user_version=999")
    from oberhau.database import Database

    with pytest.raises(OberhauError):
        Database(source)
