"""Windows committed-memory ceiling and parent-exit cleanup for the parser only."""

import ctypes
from ctypes import wintypes

from oberhau.core import OberhauError


class BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong),
        ("job_time", ctypes.c_longlong),
        ("flags", wintypes.DWORD),
        ("minimum_working_set", ctypes.c_size_t),
        ("maximum_working_set", ctypes.c_size_t),
        ("active_processes", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority", wintypes.DWORD),
        ("scheduling", wintypes.DWORD),
    ]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", BasicLimits),
        ("io", ctypes.c_ulonglong * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t),
        ("peak_job_memory", ctypes.c_size_t),
    ]


class ParserJob:
    def __init__(self, pid: int, memory_mib: int):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel = self.kernel
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        self.limit_bytes = memory_mib * 1024 * 1024
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OberhauError("Windows parser quota could not be created")
        process_handle = None
        try:
            limits = ExtendedLimits()
            # JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
            limits.basic.flags = 0x100 | 0x2000
            limits.process_memory = self.limit_bytes
            if not kernel.SetInformationJobObject(
                self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            ):
                raise OberhauError("Windows parser memory ceiling could not be applied")
            # PROCESS_SET_QUOTA | PROCESS_TERMINATE, for this owned child PID only.
            process_handle = kernel.OpenProcess(0x100 | 0x1, False, pid)
            if not process_handle or not kernel.AssignProcessToJobObject(
                self.handle, process_handle
            ):
                raise OberhauError("Windows parser could not join its resource job")
        except BaseException:
            self.close()
            raise
        finally:
            if process_handle:
                kernel.CloseHandle(process_handle)

    def metrics(self) -> dict:
        limits = ExtendedLimits()
        measured = bool(
            self.handle
            and self.kernel.QueryInformationJobObject(
                self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits), None
            )
        )
        return {
            "enforced": True,
            "limit_committed_bytes": self.limit_bytes,
            "peak_committed_bytes": limits.peak_process_memory if measured else None,
            "scope": "Windows parser job only; committed virtual memory, not RSS or GPU",
        }

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
