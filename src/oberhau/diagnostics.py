from __future__ import annotations

import importlib.metadata
import os
import platform
import shutil
import sys
from pathlib import Path

from oberhau.core import Limits, OberhauError, now
from oberhau.ollama import Ollama
from oberhau.resources import gpu_status, memory_status
from oberhau.scanners.external import capabilities
from oberhau.security import ProcessRunner


def ollama_executable() -> str | None:
    installed = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Ollama/ollama.exe"
    return shutil.which("ollama") or (
        str(installed) if installed.is_absolute() and installed.is_file() else None
    )


def collect(limits: Limits | None = None, home: Path | None = None) -> dict:
    result = {
        "checked": now(),
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "cpu_logical": __import__("os").cpu_count(),
        "git": shutil.which("git"),
        "ollama_executable": ollama_executable(),
        "scanners": capabilities(ProcessRunner(limits or Limits(timeout=10), home=home)),
        "packages": {},
    }
    if home is not None:
        from oberhau.tooling import cache_status

        result["offline_caches"] = cache_status(home)
    for name in ("PySide6-Essentials", "pydantic"):
        try:
            result["packages"][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result["packages"][name] = "missing"
    try:
        result["ollama_models"] = Ollama(timeout=3).models()
        result["qwen_available"] = "qwen3.5:4b" in result["ollama_models"]
    except OberhauError as error:
        result["ollama_error"] = str(error)
        result["qwen_available"] = False
    result["memory"] = memory_status()
    result["gpu"] = gpu_status()
    if Path(sys.executable).is_file():
        result["runtime"] = "operational"
    return result
