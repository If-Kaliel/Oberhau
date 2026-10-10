import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from time import monotonic

import pytest

from oberhau.core import Cancelled, DraftText, OberhauError, Status
from oberhau.ollama import Ollama, evidence_json, generation_lock, validate_claims
from oberhau.python_analysis import source_trace
from oberhau.reporting import generate, report_evidence
from oberhau.resources import memory_status, numeric


def test_assignment_slice_follows_reassignment_and_known_flask_input():
    source = 'from flask import request as r\ndef handler(db):\n    query = r.args.get("q")\n    query = "SELECT " + query\n    db.execute(query)\nhandler(connection)\n'
    trace = source_trace(source, 5, "python-sql-format")
    assert trace["available"] and trace["function"] == "handler"
    assert [step["line"] for step in trace["assignments"]] == [3, 4]
    assert trace["sources"][0]["kind"] == "Flask request input"
    assert trace["same_name_call_sites"][0]["line"] == 6
    assert trace["limitations"]


@pytest.mark.parametrize(
    "code,line",
    [
        ('from flask import request\ndef handler(request):\n    eval(request.args.get("q"))', 3),
        (
            'from flask import request\ndef handler():\n    request = replacement\n    eval(request.args.get("q"))',
            4,
        ),
        ("def handler(input):\n    eval(input())", 2),
        (
            'def unrelated():\n    from flask import request\ndef handler():\n    eval(request.args.get("q"))',
            4,
        ),
    ],
)
def test_shadowed_imports_and_builtins_are_not_trusted_sources(code, line):
    trace = source_trace(code, line, "python-dynamic-code")
    assert not any(
        s["kind"] in {"Flask request input", "interactive input"} for s in trace["sources"]
    )


def test_slice_redacts_secrets_and_does_not_invent_parameter_trust():
    trace = source_trace(
        'def parse(value):\n    password = "private_credential_123"\n    eval(value + password)',
        3,
        "python-dynamic-code",
    )
    assert "private_credential_123" not in json.dumps(trace)
    assert "caller trust unknown" in trace["sources"][0]["kind"]
    assert not source_trace('eval("constant")', 1, "eval")["sources"]
    assert not source_trace("broken(\n", 1, "eval")["available"]


def test_report_rechecks_source_without_changing_human_review(engine, scanned):
    identifier = engine.db.query("SELECT id FROM findings LIMIT 1")[0]["id"]
    engine.db.review(identifier, Status.VERIFIED, "Human investigation recorded")
    assert report_evidence(engine.db, identifier)["ready_for_human_review"]
    finding = engine.db.finding(identifier)["finding"]
    target = Path(finding.evidence["snapshot"]) / finding.path
    target.write_text("print('changed')\n", encoding="utf-8")
    quality = report_evidence(engine.db, identifier)
    assert quality["source_integrity"] == "changed" and not quality["ready_for_human_review"]
    assert quality["python_analysis"] is None
    _, report = generate(engine.db, identifier)
    assert "Evidence incomplete" in report
    assert engine.db.finding(identifier)["status"] == Status.VERIFIED
    target.unlink()
    assert report_evidence(engine.db, identifier)["source_integrity"] == "unavailable"


def test_context_preserves_valid_json_and_utf8_budget():
    content, truncated = evidence_json({f"field{i}": "漢🙂" * 3000 for i in range(25)})
    assert truncated and len(content.encode("utf-8")) <= 6000
    assert isinstance(json.loads(content), dict)
    assert evidence_json({"context": "small"}) == ('{"context": "small"}', False)
    assert evidence_json({"a": "long"}, budget=2) == ("{}", True)


def draft(summary):
    return DraftText(
        summary=summary, explanation="Provisional", remediation="Review", limitations="Unverified"
    )


@pytest.mark.parametrize(
    "claim", ["CVE-2026-12345", "GHSA-abcd-1234-5678", "https://invented.example/impact"]
)
def test_claim_guard_rejects_advisories_and_urls_without_recorded_evidence(claim):
    with pytest.raises(OberhauError):
        validate_claims(draft(claim), {"context": claim})
    validate_claims(draft(claim), {"advisories": [claim], "allowed_urls": [claim]})


@pytest.mark.parametrize("response", [[], {"done": False}, {"done_reason": "length"}])
def test_invalid_or_incomplete_model_outputs_fail(monkeypatch, response):
    client = Ollama()
    monkeypatch.setattr(client, "request", lambda *args: response)
    with pytest.raises(OberhauError):
        client.draft({})


def test_generation_queue_is_cancellable():
    ready, release = Event(), Event()

    def occupy():
        with generation_lock(Event(), 3):
            ready.set()
            release.wait(3)

    thread = Thread(target=occupy)
    thread.start()
    try:
        assert ready.wait(2)
        with pytest.raises(OberhauError, match="busy"):
            with generation_lock(Event(), 0.2):
                pytest.fail("Concurrent generation entered")
        cancelled = Event()
        cancelled.set()
        with pytest.raises(Cancelled):
            with generation_lock(cancelled, 1):
                pytest.fail("Cancelled generation entered")
    finally:
        release.set()
        thread.join(3)


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex coordination")
def test_generation_mutex_serializes_independent_processes(tmp_path):
    marker = tmp_path / "entered"
    code = 'from threading import Event\nfrom pathlib import Path\nfrom oberhau.ollama import generation_lock\nprint("waiting",flush=True)\nwith generation_lock(Event(),3):\n Path(__import__("sys").argv[1]).write_text("entered")\n'
    with generation_lock(Event(), 3):
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(marker)], stdout=subprocess.PIPE, text=True
        )
        try:
            # The parent owns the named mutex; child cannot enter even though its Python lock is free.
            assert process.stdout.readline().strip() == "waiting"
            with pytest.raises(subprocess.TimeoutExpired):
                process.wait(timeout=0.2)
            assert not marker.exists()
            assert process.poll() is None
        except BaseException:
            process.kill()
            process.wait()
            raise
    assert process.wait(timeout=5) == 0 and marker.read_text() == "entered"
    process.stdout.close()


def test_cancel_interrupts_close_header_http_body_read():
    entered, release = Event(), Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.send_header("Connection", "close")
            self.end_headers()
            entered.set()
            release.wait(5)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    serving = Thread(target=server.serve_forever, daemon=True)
    serving.start()
    cancel = Event()
    errors = []

    def request():
        try:
            Ollama(f"http://127.0.0.1:{server.server_port}", timeout=5).request(
                "/api/tags", cancel=cancel
            )
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=request)
    thread.start()
    try:
        assert entered.wait(2)
        started = monotonic()
        cancel.set()
        thread.join(2)
        assert not thread.is_alive() and monotonic() - started < 2
        assert isinstance(errors[0], Cancelled)
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_windows_memory_probe_and_optional_numeric_values():
    status = memory_status()
    if os.name == "nt":
        assert status["available"] and 0 <= status["available_bytes"] <= status["total_bytes"]
        assert 0 <= status["load_percent"] <= 100
    assert numeric("N/A") is None and numeric(" 4096 ") == 4096
