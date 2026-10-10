"""Trusted loopback HTTP recipes, independent of all imported source."""

from __future__ import annotations

import http.client
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from urllib.parse import urlsplit

from oberhau.core import OberhauError, now
from oberhau.framework_analysis import checkpoint

RECIPES = {"authorization", "input-validation"}


def validate_local(db, recipe: str, cancel: Event | None = None) -> dict:
    if recipe not in RECIPES:
        raise OberhauError("Unknown trusted local validation recipe")
    cancel = cancel or Event()
    deadline = time.monotonic() + 10
    checkpoint(cancel, deadline)
    # Fixed synthetic records and handler code; no source path or target URL input.
    records = {
        "1": {"owner": "alice", "content": "SYNTHETIC ALICE DOCUMENT"},
        "2": {"owner": "bob", "content": "SYNTHETIC BOB DOCUMENT"},
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            parts = urlsplit(self.path).path.strip("/").split("/")
            corrected = parts[0] == "fixed"
            identifier = parts[-1]
            if recipe == "authorization":
                value = records.get(identifier)
                status = (
                    404
                    if value is None
                    else 403
                    if corrected and value["owner"] != self.headers.get("X-Synthetic-User")
                    else 200
                )
                output = (
                    {"content": value["content"]}
                    if status == 200
                    else {"error": "resource unavailable"}
                )
            else:
                try:
                    count = int(identifier)
                except ValueError:
                    count = 0
                status = 400 if corrected and not 1 <= count <= 10 else 200
                output = (
                    {"accepted_count": count}
                    if status == 200
                    else {"error": "count outside synthetic 1..10 range"}
                )
            payload = json.dumps(output).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    serving = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    serving.start()
    results = []
    try:
        identifier = "2" if recipe == "authorization" else "-7"
        for variant in ("vulnerable", "fixed"):
            checkpoint(cancel, deadline)
            # Exact listener address, no DNS, proxies, redirects or third-party requests.
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                connection.request(
                    "GET", f"/{variant}/{identifier}", headers={"X-Synthetic-User": "alice"}
                )
                response = connection.getresponse()
                payload = response.read(4097)
                if len(payload) > 4096:
                    raise OberhauError("Trusted lab response exceeds limit")
                results.append(
                    {"variant": variant, "status": response.status, "body": json.loads(payload)}
                )
            finally:
                connection.close()
        checkpoint(cancel, deadline)
    finally:
        server.shutdown()
        server.server_close()
        serving.join(2)
    expected_fixed = 403 if recipe == "authorization" else 400
    result = {
        "recipe": recipe,
        "passed": results[0]["status"] == 200 and results[1]["status"] == expected_fixed,
        "environment": "Disposable trusted HTTP listener on 127.0.0.1, ephemeral port",
        "synthetic_input": {"user": "alice", "identifier": identifier},
        "expected": {"vulnerable_status": 200, "fixed_status": expected_fixed},
        "observed": results,
        "limitations": "Validates bundled trusted recipe behavior only; never reproduces or verifies a hypothesis in imported source",
        "created": now(),
    }
    db.execute(
        "INSERT INTO validations(finding_id,result,created) VALUES(NULL,?,?)",
        (json.dumps(result), now()),
    )
    db.audit("laboratory.local-http", result)
    return result
