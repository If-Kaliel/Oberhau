"""Read-only Windows RAM and NVIDIA telemetry; all probes are optional."""

import csv
import os
from pathlib import Path
from threading import Event

from oberhau.core import Limits, OberhauError
from oberhau.security import ProcessRunner


def memory_status() -> dict:
    if os.name != "nt":
        return {"available": False}
    import ctypes
    from ctypes import wintypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("load", wintypes.DWORD),
            *[
                (name, ctypes.c_ulonglong)
                for name in (
                    "total",
                    "free",
                    "page_total",
                    "page_free",
                    "virtual_total",
                    "virtual_free",
                    "extended",
                )
            ],
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatus)]
    kernel.GlobalMemoryStatusEx.restype = wintypes.BOOL
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(status)):
        return {"available": False}
    return {
        "available": True,
        "total_bytes": status.total,
        "available_bytes": status.free,
        "load_percent": status.load,
    }


def gpu_status() -> dict:
    candidates = [
        Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/nvidia-smi.exe",
        Path(os.environ.get("ProgramFiles", "C:/Program Files"))
        / "NVIDIA Corporation/NVSMI/nvidia-smi.exe",
    ]
    binary = next((path for path in candidates if path.is_file()), None)
    if binary is None:
        return {"available": False, "reason": "NVIDIA telemetry utility unavailable"}
    try:
        payload = ProcessRunner(Limits(timeout=5), {"nvidia-smi": str(binary)}).run(
            "nvidia-smi",
            [
                "--query-gpu=name,memory.total,memory.used,utilization.gpu,temperature.gpu,driver_version",
                "--format=csv,noheader,nounits",
            ],
            Path.cwd(),
            Event(),
        )
        devices = []
        for row in csv.reader(payload.splitlines()):
            if len(row) != 6:
                raise OberhauError("Unsupported NVIDIA telemetry response")
            devices.append(
                {
                    "name": row[0].strip(),
                    "memory_total_mib": numeric(row[1]),
                    "memory_used_mib": numeric(row[2]),
                    "utilization_percent": numeric(row[3]),
                    "temperature_c": numeric(row[4]),
                    "driver": row[5].strip(),
                }
            )
        return {"available": True, "devices": devices}
    except (OberhauError, OSError) as error:
        return {"available": False, "reason": str(error)}


def numeric(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def process_memory() -> dict:
    """Actual process-wide Windows working set; native parser allocations are included."""
    if os.name != "nt":
        return {"available": False}
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("faults", wintypes.DWORD),
            *[
                (name, ctypes.c_size_t)
                for name in (
                    "peak_working_set",
                    "working_set",
                    "peak_paged",
                    "paged",
                    "peak_nonpaged",
                    "nonpaged",
                    "pagefile",
                    "peak_pagefile",
                    "private",
                )
            ],
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(Counters),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    if not psapi.GetProcessMemoryInfo(
        kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    ):
        return {"available": False}
    return {
        "available": True,
        "working_set_bytes": counters.working_set,
        "peak_working_set_bytes": counters.peak_working_set,
        "private_commit_bytes": counters.private,
        "scope": "Whole process including native allocations; peak includes earlier and concurrent work",
    }
