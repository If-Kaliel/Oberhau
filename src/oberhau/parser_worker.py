"""Private bounded JSON protocol: imported source is parsed as bytes, never executed."""

from __future__ import annotations

import base64
import json
import sys
import time
from threading import Event

from oberhau.framework_analysis import parse_file
from oberhau.security import sanitize

MAX_REQUEST_BYTES = 28_000_000  # Existing 20 MB source-file ceiling after base64.
MAX_RESPONSE_BYTES = 8_000_000


def main() -> int:
    source, target = sys.stdin.buffer, sys.stdout.buffer
    while raw := source.readline(MAX_REQUEST_BYTES + 1):
        if len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
            return 2
        try:
            request = json.loads(raw)
            if set(request) != {"path", "sha256", "content", "seconds"}:
                return 2
            seconds = request["seconds"]
            if not isinstance(seconds, (int, float)) or not 0 < seconds <= 60:
                return 2
            content = base64.b64decode(request["content"], validate=True)
            if len(content) > 20_000_000:
                return 2
            summary = parse_file(
                request["path"], request["sha256"], content, Event(), time.monotonic() + seconds
            )
            payload = {"summary": sanitize(summary.model_dump())}
        except Exception:
            # Exception messages may contain source fragments; do not transport them.
            payload = {"error": "Parser could not complete the file"}
        response = json.dumps(payload, ensure_ascii=True).encode() + b"\n"
        if len(response) > MAX_RESPONSE_BYTES:
            response = b'{"error":"Parser response budget exceeded"}\n'
        target.write(response)
        target.flush()
    return 0


def dispatch() -> None:
    """Called before argument parsing in both trusted frozen entry points."""
    if sys.argv[1:] == ["--oberhau-parser-worker"]:
        raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
