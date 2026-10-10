"""Keep dynamic library directories private to the frozen app, not inherited by scanners."""

import ctypes
import os
import sys
from pathlib import Path

_directories = []


def prepare_runtime() -> None:
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return
    from ctypes import wintypes

    # Resolve the known Qt dependency set before clearing inherited DLL directories.
    from PySide6 import QtCore, QtGui, QtNetwork, QtSvg, QtWidgets  # noqa: F401

    root = Path(sys._MEIPASS).resolve()
    # AddDllDirectory supports imports/plugins in this process without the child inheritance
    # of PyInstaller's SetDllDirectory. Hold its handles for the lifetime of the application.
    for directory in (root, root / "PySide6", root / "shiboken6"):
        if directory.is_dir():
            _directories.append(os.add_dll_directory(str(directory)))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetDllDirectoryW.argtypes = [wintypes.LPCWSTR]
    kernel.SetDllDirectoryW.restype = wintypes.BOOL
    if not kernel.SetDllDirectoryW(None):
        raise RuntimeError("Unable to isolate frozen library search paths")
    os.environ["PATH"] = os.pathsep.join(
        value
        for value in os.environ.get("PATH", "").split(os.pathsep)
        if value and not Path(value).resolve().is_relative_to(root)
    )
