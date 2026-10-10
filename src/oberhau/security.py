from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from threading import Event
from typing import Any
from urllib.parse import urlsplit

from oberhau.core import Cancelled, Limits, OberhauError

SECRET_PATTERNS = [
    re.compile(
        r"(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\"']?\s*[=:]\s*)[^\r\n,;]+"
    ),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"),
    re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"),
]


def redact(text: str) -> str:
    for index, pattern in enumerate(SECRET_PATTERNS):
        text = pattern.sub(
            (lambda m: m.group(1) + "[REDACTED]") if index in (0, 4) else "[REDACTED]",
            text,
        )
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32)


def sanitize(value: Any) -> Any:
    """Redact string leaves before serialization, keeping JSON structurally valid."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if re.fullmatch(r"(?i)(secret|token|password|api_key)", key)
                else sanitize(item)
            )
            for key, item in value.items()
        }
    return value


def redact_source(text: str) -> str:
    """Redact before selecting excerpts while preserving source line numbering."""
    text = SECRET_PATTERNS[3].sub(
        lambda match: "\n".join("[REDACTED PRIVATE KEY]" for _ in match.group(0).splitlines()),
        text,
    )
    return redact(text)


def confined(root: Path, relative: str) -> Path:
    if "\\" in relative or ":" in relative or relative.startswith("/"):
        raise OberhauError("Unsafe file path")
    candidate = root / relative
    if any(part in ("..", "") for part in Path(relative).parts):
        raise OberhauError("Unsafe file path")
    for part in Path(relative).parts:
        if part.endswith((".", " ")) or part.split(".")[0].upper() in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *{f"COM{i}" for i in range(1, 10)},
            *{f"LPT{i}" for i in range(1, 10)},
        }:
            raise OberhauError("Unsafe Windows file name")
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise OberhauError("Path escapes project boundary")
    for part in (candidate, *candidate.parents):
        if part == root.parent:
            break
        if part.is_symlink() or part.is_junction():
            raise OberhauError("Symbolic links and junctions are not accepted")
    return candidate


def local_ollama_url(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise OberhauError("Ollama must use a local loopback HTTP endpoint")
    return url.rstrip("/")


class ProcessRunner:
    """Only registered tool binaries; no shells, repository executables, or generated commands."""

    def __init__(self, limits: Limits, tools: dict[str, str] | None = None):
        self.limits = limits
        self.tools = (
            tools
            if tools is not None
            else {
                name: path
                for name in ("git", "semgrep", "gitleaks", "osv-scanner", "trivy")
                if (path := shutil.which(name))
            }
        )

    def run(
        self,
        tool: str,
        args: list[str],
        cwd: Path,
        cancel: Event,
        allowed_codes: tuple[int, ...] = (0,),
    ) -> str:
        binary = self.tools.get(tool)
        if not binary or not Path(binary).is_file():
            raise OberhauError(f"{tool}: executable not installed")
        if Path(binary).resolve().is_relative_to(cwd.resolve()):
            raise OberhauError("Refusing to execute a tool inside the untrusted project")
        if any("\0" in arg for arg in args):
            raise OberhauError("Invalid tool argument")
        if cancel.is_set():
            raise Cancelled()
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("GIT_", "SEMGREP_", "GITLEAKS_"))
        }
        # Do not pass operator credentials or interpreter injection to scanners.
        for key in list(env):
            if re.search(r"(?i)(token|secret|password|api_key)", key) or key in {
                "PYTHONPATH",
                "PYTHONHOME",
                "NODE_OPTIONS",
                "LD_PRELOAD",
            }:
                env.pop(key)
        env.update(
            {
                "SEMGREP_SEND_METRICS": "off",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        flags = (
            subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            if os.name == "nt"
            else 0
        )
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen(
                [binary, *args],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                shell=False,
                creationflags=flags,
                start_new_session=os.name != "nt",
            )
            deadline = time.monotonic() + self.limits.timeout
            try:
                while process.poll() is None:
                    if cancel.wait(0.05):
                        raise Cancelled()
                    if time.monotonic() > deadline:
                        raise OberhauError(f"{tool}: timeout")
                    if out.tell() + err.tell() > self.limits.max_output_bytes:
                        raise OberhauError(f"{tool}: output limit exceeded")
                if out.tell() + err.tell() > self.limits.max_output_bytes:
                    raise OberhauError(f"{tool}: output limit exceeded")
                out.seek(0)
                err.seek(0)
                result = out.read(self.limits.max_output_bytes).decode("utf-8", errors="replace")
                error = err.read(8000).decode("utf-8", errors="replace")
                if process.returncode not in allowed_codes:
                    raise OberhauError(f"{tool}: exit {process.returncode}: {redact(error)}")
                return result
            finally:
                if process.poll() is None:
                    if os.name == "nt":
                        subprocess.run(
                            [
                                str(
                                    Path(os.environ.get("SystemRoot", "C:/Windows"))
                                    / "System32/taskkill.exe"
                                ),
                                "/PID",
                                str(process.pid),
                                "/T",
                                "/F",
                            ],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=10,
                        )
                    else:
                        import signal

                        os.killpg(process.pid, signal.SIGKILL)
                    process.kill()
                process.wait(timeout=10)
