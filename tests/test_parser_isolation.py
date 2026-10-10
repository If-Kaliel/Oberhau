import hashlib
import json
import os
import sys
import time
from threading import Event, Timer

import pytest

from oberhau.core import Cancelled, OberhauError
from oberhau.parser_isolation import ParserSession


def assert_reaped(session):
    assert session.process.poll() is not None
    assert session.transport is None or not session.transport.is_alive()
    assert session.process.stdin.closed and session.process.stdout.closed


def test_real_session_reuses_process_and_never_executes_source(tmp_path):
    marker = tmp_path / "executed"
    code = f"from pathlib import Path\nPath({str(marker)!r}).touch()\ndef foo():\n return open('x')\n".encode()
    with ParserSession(Event(), time.monotonic() + 20) as session:
        result = session.parse("never.py", hashlib.sha256(code).hexdigest(), code)
        assert result.symbols[0].calls[0]["name"] == "open"
        pid = session.process.pid
        second = session.parse("route.ts", "a" * 64, b"export function GET(req: Request) {}")
        assert second.symbols[0].endpoint == "GET ."
        assert session.process.pid == pid and session.process.poll() is None
    assert not marker.exists()
    assert_reaped(session)


@pytest.mark.parametrize("mode", ["deadline", "cancel"])
def test_hung_child_is_reaped_even_when_large_pipe_write_blocks(monkeypatch, mode):
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command",
        lambda: [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
    )
    cancel = Event()
    session = ParserSession(cancel, time.monotonic() + 10, file_timeout=0.5)
    timer = Timer(0.2, cancel.set) if mode == "cancel" else None
    if timer:
        timer.start()
    begin = time.monotonic()
    try:
        with pytest.raises(Cancelled if timer else OberhauError):
            session.parse("huge.ts", "a" * 64, b" " * 2_000_000)
    finally:
        if timer:
            timer.cancel()
            timer.join()
        session.close()
    assert time.monotonic() - begin < 4
    assert_reaped(session)


def test_child_crash_does_not_crash_parent_or_reuse_failed_session(monkeypatch):
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command",
        lambda: [sys.executable, "-I", "-c", "import os; os._exit(7)"],
    )
    session = ParserSession(Event(), time.monotonic() + 10)
    with pytest.raises(OberhauError, match="parser"):
        session.parse("route.ts", "a" * 64, b"x")
    assert session.process.returncode == 7
    assert_reaped(session)
    with pytest.raises(OberhauError, match="closed"):
        session.parse("route.ts", "a" * 64, b"x")


@pytest.mark.parametrize(
    "response", ["{", "null", "42", '{"summary":{}}', '{"error":"secret raw source"}']
)
def test_invalid_protocol_fails_without_exposing_child_text(monkeypatch, response):
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command",
        lambda: [
            sys.executable,
            "-I",
            "-c",
            f"import sys; sys.stdin.readline(); print({response!r}, flush=True)",
        ],
    )
    session = ParserSession(Event(), time.monotonic() + 10)
    with pytest.raises(OberhauError) as error:
        session.parse("route.ts", "a" * 64, b"x")
    assert "secret raw source" not in str(error.value)
    assert_reaped(session)


def test_crashed_parser_run_is_failed_and_publishes_no_contextual_findings(
    engine, tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "route.ts").write_text("export function GET(req: Request) {}")
    project = engine.ingestion.add(source, "Owned crash fixture")
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command",
        lambda: [sys.executable, "-I", "-c", "import os; os._exit(7)"],
    )
    engine.scan(project, "research")
    row = engine.db.query("SELECT * FROM research_runs")[0]
    assert row["status"] == "failed" and json.loads(row["errors"])
    assert not engine.db.query(
        "SELECT * FROM findings WHERE json_extract(data,'$.scanner')='contextual'"
    )


def test_cancellation_before_spawn_creates_no_process():
    cancel = Event()
    cancel.set()
    session = ParserSession(cancel, time.monotonic() + 10)
    with pytest.raises(Cancelled):
        session.parse("route.ts", "a" * 64, b"x")
    assert session.process is None


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object committed-memory ceiling")
def test_windows_denies_allocation_above_parser_memory_ceiling(monkeypatch):
    command = "import sys\nsys.stdin.readline()\ntry:\n data = bytearray(256 * 1024 * 1024)\nexcept MemoryError:\n sys.exit(93)\nprint('unexpected allocation success', flush=True)"
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command", lambda: [sys.executable, "-I", "-c", command]
    )
    session = ParserSession(Event(), time.monotonic() + 10, memory_mib=128)
    with pytest.raises(OberhauError):
        session.parse("route.ts", "a" * 64, b"x")
    assert session.process.returncode == 93
    assert_reaped(session)


def test_worker_identity_mismatch_is_rejected(monkeypatch):
    payload = json.dumps({"summary": {"path": "other.ts", "sha256": "b" * 64, "parser": "test"}})
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command",
        lambda: [
            sys.executable,
            "-I",
            "-c",
            f"import sys; sys.stdin.readline(); print({payload!r}, flush=True)",
        ],
    )
    session = ParserSession(Event(), time.monotonic() + 10)
    with pytest.raises(OberhauError, match="identity"):
        session.parse("route.ts", "a" * 64, b"x")
    assert_reaped(session)


def test_oversized_child_response_is_bounded_and_reaped(monkeypatch):
    monkeypatch.setattr("oberhau.parser_isolation.MAX_RESPONSE_BYTES", 4096)
    command = "import sys; sys.stdin.readline(); sys.stdout.write('x' * 8192); sys.stdout.flush()"
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command", lambda: [sys.executable, "-I", "-c", command]
    )
    session = ParserSession(Event(), time.monotonic() + 10)
    with pytest.raises(OberhauError, match="budget"):
        session.parse("route.ts", "a" * 64, b"x")
    assert_reaped(session)
