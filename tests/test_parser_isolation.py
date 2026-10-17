import hashlib
import json
import os
import sys
import time
from pathlib import Path
from threading import Event, Timer

import pytest

from oberhau import parser_isolation
from oberhau.core import Cancelled, OberhauError
from oberhau.parser_isolation import ParserFileError, ParserSession


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


ROUTE = "export function GET(req: Request, params: any) { return db.user.findUnique({where:{id:params.id}}); }"
WORKER = """
import base64, json, os, sys, time
sys.path.insert(0, sys.argv[1])
from threading import Event
from oberhau.framework_analysis import parse_file
behaviors = json.loads(sys.argv[2])
while raw := sys.stdin.buffer.readline():
    request = json.loads(raw)
    action = behaviors.get(request["path"], "")
    if action == "crash":
        os._exit(9)
    if action == "hang":
        time.sleep(30)
    if action.startswith("reply:"):
        print(action[6:], flush=True)
        continue
    content = base64.b64decode(request["content"])
    deadline = time.monotonic() + 10
    summary = parse_file(request["path"], request["sha256"], content, Event(), deadline)
    print(json.dumps({"summary": summary.model_dump()}), flush=True)
"""


def research_project(engine, tmp_path, files):
    source = tmp_path / "source"
    for path, text in {"app/users/route.ts": ROUTE, **files}.items():
        (source / path).parent.mkdir(parents=True, exist_ok=True)
        (source / path).write_text(text)
    return engine.ingestion.add(source, "Owned parser gap fixture")


def latest_run(engine):
    return engine.db.query("SELECT * FROM research_runs ORDER BY id DESC")[0]


def contextual_findings(engine):
    return engine.db.query(
        "SELECT * FROM findings WHERE json_extract(data,'$.scanner')='contextual'"
    )


def scripted_worker(monkeypatch, behaviors):
    """Real parser for most paths; owned per-path crash, hang or raw protocol replies."""
    root = str(Path(parser_isolation.__file__).resolve().parents[1])
    command = [sys.executable, "-I", "-c", WORKER, root, json.dumps(behaviors)]
    monkeypatch.setattr("oberhau.parser_isolation.worker_command", lambda: command)


def test_parser_budget_refusal_is_an_explicit_coverage_gap(engine, tmp_path):
    # More than the 200,000-node file syntax budget, as in a minified bundle outside dist/build.
    # Root files index before app/, so the endpoint needs a fresh worker after the refusal.
    bundle = "export const secretBundleMarker = [" + "0," * 200_001 + "];"
    project = research_project(engine, tmp_path, {"vendor.js": bundle})
    engine.scan(project, "research")
    run = latest_run(engine)
    assert run["status"] == "completed"
    assert "secretBundleMarker" not in run["data"]
    data = json.loads(run["data"])
    assert data["coverage"]["vendor.js"] == {
        "parser": "unavailable",
        "limitations": [
            "Parser coverage gap: File syntax node budget exceeded; file excluded from contextual paths"
        ],
    }
    assert data["coverage"]["app/users/route.ts"]["parser"] == "tree-sitter:next-node"
    assert data["index"]["parsed"] == 1 and data["index"]["parser_gaps"] == 1
    assert data["index"]["parser_memory"]["workers"] == 2
    note = "Parser coverage gaps: 1 file(s) excluded"
    assert any(item.startswith(note) for item in data["limitations"])
    assert [h["path"] for h in data["hypotheses"]] == ["app/users/route.ts"]
    assert any(item.startswith(note) for item in data["hypotheses"][0]["limitations"])
    assert len(contextual_findings(engine)) == 1
    provenance = engine.db.query("SELECT provenance FROM scanner_runs WHERE scanner='contextual'")
    assert json.loads(provenance[0]["provenance"])["parser_gaps"] == ["vendor.js"]
    assert not engine.db.query("SELECT * FROM research_files WHERE path='vendor.js'")
    engine.scan(project, "research")
    repeated = json.loads(latest_run(engine)["data"])
    # Gaps are never cached: the next run retries the file and reuses the endpoint summary.
    assert repeated["index"]["reused"] == 1 and repeated["index"]["parser_gaps"] == 1
    assert repeated["changes"][0]["state"] == "previously-observed"


def test_crash_deadline_and_error_reply_are_gaps_with_fixed_reasons(engine, tmp_path, monkeypatch):
    project = research_project(engine, tmp_path, {"crash.ts": "x", "hang.ts": "x", "reply.ts": "x"})
    scripted_worker(
        monkeypatch,
        {
            "crash.ts": "crash",
            "hang.ts": "hang",
            "reply.ts": 'reply:{"error": "secret raw source"}',
        },
    )
    engine.db.set_setting("research_limits", {"parser_timeout_seconds": 1})
    engine.scan(project, "research")
    run = latest_run(engine)
    assert run["status"] == "completed"
    assert "secret raw source" not in run["data"]
    coverage = json.loads(run["data"])["coverage"]
    reasons = {
        path: coverage[path]["limitations"][0] for path in ("crash.ts", "hang.ts", "reply.ts")
    }
    assert reasons == {
        "crash.ts": "Parser coverage gap: Isolated parser exited unexpectedly; file excluded from contextual paths",
        "hang.ts": "Parser coverage gap: Isolated parser file deadline exceeded; file excluded from contextual paths",
        "reply.ts": "Parser coverage gap: Parser could not complete the file; file excluded from contextual paths",
    }
    assert len(contextual_findings(engine)) == 1


def test_hypothesis_lost_to_a_gap_is_unobserved_not_resolved(engine, tmp_path, monkeypatch):
    project = research_project(engine, tmp_path, {})
    engine.scan(project, "research")
    (tmp_path / "source/app/users/route.ts").write_text(ROUTE + "\n// changed")
    engine.refresh_project(project)
    scripted_worker(monkeypatch, {"app/users/route.ts": "crash"})
    engine.scan(project, "research")
    run = latest_run(engine)
    assert run["status"] == "completed"
    assert [c["state"] for c in json.loads(run["data"])["changes"]] == ["unobserved-coverage-gap"]


def test_controls_in_gap_files_are_unobserved_not_removed():
    from oberhau.git_intelligence import changes

    control = {"kind": "control", "path": "middleware.ts", "label": "middleware"}
    previous = {"graph": {"nodes": [control]}}
    result = changes(previous, {"graph": {"nodes": []}}, {}, {}, {"middleware.ts"})
    assert result["controls_removed"] == []
    assert result["controls_unobserved"] == [{"path": "middleware.ts", "control": "middleware"}]
    assert changes(previous, {}, {}, {})["controls_removed"] == result["controls_unobserved"]


@pytest.mark.parametrize(
    "reply,match",
    [
        ("reply:{", "invalid response"),
        ("reply:" + json.dumps({"summary": {}, "error": "x"}), "invalid response"),
        (
            "reply:"
            + json.dumps({"summary": {"path": "other.ts", "sha256": "b" * 64, "parser": "x"}}),
            "identity",
        ),
    ],
)
def test_protocol_violations_still_fail_the_run(engine, tmp_path, monkeypatch, reply, match):
    project = research_project(engine, tmp_path, {"bad.ts": "x"})
    scripted_worker(monkeypatch, {"bad.ts": reply})
    engine.scan(project, "research")
    run = latest_run(engine)
    assert run["status"] == "failed" and match in run["errors"]
    assert not contextual_findings(engine)


def test_broken_parser_environment_is_not_reported_as_gaps(engine, tmp_path, monkeypatch):
    project = research_project(engine, tmp_path, {})
    monkeypatch.setattr(
        "oberhau.parser_isolation.worker_command",
        lambda: [sys.executable, "-I", "-c", "import os; os._exit(7)"],
    )
    engine.scan(project, "research")
    run = latest_run(engine)
    assert run["status"] == "failed" and "control file" in run["errors"]
    assert not contextual_findings(engine)


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_cancellation_and_run_deadline_during_a_file_failure_stay_fatal(
    engine, tmp_path, monkeypatch, stop
):
    project = research_project(engine, tmp_path, {})

    def failing(self, path, digest, content):
        if stop == "cancel":
            self.cancel.set()
        else:
            time.sleep(max(0, self.deadline - time.monotonic()) + 0.05)
        raise ParserFileError("Isolated parser file deadline exceeded")

    monkeypatch.setattr(ParserSession, "parse", failing)
    engine.limits.timeout = 1
    engine.scan(project, "research")
    run = latest_run(engine)
    assert run["status"] == ("cancelled" if stop == "cancel" else "failed")
    if stop == "deadline":
        assert "Contextual investigation deadline exceeded" in run["errors"]
    assert not contextual_findings(engine)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object attachment")
def test_parser_quota_attachment_failure_stays_fatal(engine, tmp_path, monkeypatch):
    project = research_project(engine, tmp_path, {})

    def refuse(*_):
        raise OberhauError("Windows parser quota could not be created")

    monkeypatch.setattr("oberhau.parser_job.ParserJob", refuse)
    engine.scan(project, "research")
    run = latest_run(engine)
    assert run["status"] == "failed" and "quota" in run["errors"]


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
