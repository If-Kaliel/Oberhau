"""One killable parser process per research job; this is not an OS security sandbox."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread

from oberhau.core import OberhauError
from oberhau.framework_analysis import checkpoint
from oberhau.parser_worker import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from oberhau.research_models import FileSummary


def worker_command() -> list[str]:
    if getattr(sys, "frozen", False):
        # Windowed PyInstaller executables have no Python standard streams. Use the
        # sibling console entry with hidden Windows flags and private pipes.
        binary = Path(sys.executable).with_name("oberhau-cli.exe")
        if not binary.is_file():
            raise OberhauError("Packaged parser entry point is missing")
        return [str(binary), "--oberhau-parser-worker"]
    root = str(Path(__file__).resolve().parents[1])
    bootstrap = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from oberhau.parser_worker import main; raise SystemExit(main())"
    )
    return [sys.executable, "-I", "-c", bootstrap, root]


class ParserSession:
    def __init__(
        self, cancel: Event, deadline: float, file_timeout: float = 10, memory_mib: int = 512
    ):
        self.cancel = cancel
        self.deadline = deadline
        self.file_timeout = file_timeout
        self.memory_mib = memory_mib
        self.job = None
        self.process: subprocess.Popen | None = None
        self.transport: Thread | None = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def parse(self, path: str, digest: str, content: bytes) -> FileSummary:
        checkpoint(self.cancel, self.deadline)
        if self.closed:
            raise OberhauError("Parser session is closed")
        expires = min(self.deadline, time.monotonic() + self.file_timeout)
        if len(content) > 20_000_000:
            raise OberhauError("Parser request budget exceeded")
        request = (
            json.dumps(
                {
                    "path": path,
                    "sha256": digest,
                    "content": base64.b64encode(content).decode("ascii"),
                    "seconds": min(self.file_timeout, 60),
                },
                ensure_ascii=True,
            ).encode()
            + b"\n"
        )
        if len(request) > MAX_REQUEST_BYTES:
            raise OberhauError("Parser request budget exceeded")
        try:
            if self.process is None:
                self.process = subprocess.Popen(
                    worker_command(),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    bufsize=0,
                )
                if os.name == "nt":
                    from oberhau.parser_job import ParserJob

                    self.job = ParserJob(self.process.pid, self.memory_mib)
            process = self.process
            received = Queue(maxsize=1)

            def roundtrip():
                try:
                    # Handle short pipe writes. A hung child must not block the UI
                    # even while writing source larger than the OS pipe buffer.
                    remaining = memoryview(request)
                    while remaining:
                        count = process.stdin.write(remaining)
                        if not count:
                            raise OSError("Closed parser input")
                        remaining = remaining[count:]
                    raw = process.stdout.readline(MAX_RESPONSE_BYTES + 1)
                    received.put(raw)
                except (OSError, ValueError):
                    received.put(None)

            self.transport = Thread(target=roundtrip, name="oberhau-parser-io", daemon=True)
            self.transport.start()
            while True:
                checkpoint(self.cancel, self.deadline)
                if time.monotonic() >= expires:
                    raise OberhauError("Isolated parser file deadline exceeded")
                try:
                    raw = received.get(timeout=min(0.05, max(0.001, expires - time.monotonic())))
                    break
                except Empty:
                    if process.poll() is not None:
                        raise OberhauError("Isolated parser exited unexpectedly") from None
            self.transport.join(timeout=1)
            if not raw or len(raw) > MAX_RESPONSE_BYTES or not raw.endswith(b"\n"):
                raise OberhauError("Isolated parser failed or exceeded its response budget")
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {"summary"}:
                raise OberhauError("Isolated parser could not complete the file")
            summary = FileSummary.model_validate(payload["summary"])
            if summary.path != path or summary.sha256 != digest:
                raise OberhauError("Isolated parser returned mismatched source identity")
            checkpoint(self.cancel, self.deadline)
            return summary
        except BaseException as error:
            self.close()
            if isinstance(error, (OSError, ValueError)):
                raise OberhauError("Isolated parser returned an invalid response") from error
            raise

    def memory_metrics(self) -> dict:
        return (
            self.job.metrics()
            if self.job
            else {"enforced": False, "reason": "No Windows parser job was started"}
        )

    def close(self) -> None:
        self.closed = True
        process = self.process
        if process is None:
            return
        if self.job is not None:
            self.job.close()
        # Kill before closing pipes: another thread may be blocked in a pipe write.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if self.transport is not None:
            self.transport.join(timeout=2)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()
