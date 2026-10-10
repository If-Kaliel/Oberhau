"""Cooperative data-directory exclusion for scans, ingestion and complete backups."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from threading import local

from oberhau.core import OberhauError
from oberhau.security import confined

_local = local()


@contextmanager
def store_lock(home: Path) -> Iterator[None]:
    home = home.resolve()
    depths = getattr(_local, "depths", None)
    if depths is None:
        depths = _local.depths = {}
    key = str(home).casefold() if os.name == "nt" else str(home)
    if key in depths:
        depths[key] += 1
        try:
            yield
        finally:
            depths[key] -= 1
        return
    lockdir = confined(home, "locks")
    lockdir.mkdir(parents=True, exist_ok=True)
    path = confined(home, "locks/storage.lock")
    with path.open("a+b") as handle:
        if not path.stat().st_size:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise OberhauError(
                "Another scan, import or backup is using this data directory"
            ) from error
        depths[key] = 1
        try:
            yield
        finally:
            del depths[key]
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def storage_operation(operation: Callable) -> Callable:
    @wraps(operation)
    def guarded(self, *args, **kwargs):
        with store_lock(self.home):
            return operation(self, *args, **kwargs)

    return guarded
