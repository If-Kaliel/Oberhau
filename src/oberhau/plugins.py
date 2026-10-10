from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from threading import Event
from typing import Protocol

from oberhau.core import Finding, Limits, OberhauError


class ScannerPlugin(Protocol):
    identifier: str
    version: str
    network: bool
    active: bool
    license: str
    categories: list[str]

    def scan(
        self,
        root: Path,
        paths: list[str],
        cancel: Event,
        limits: Limits,
        progress: Callable[[str], None],
        categories: list[str] | None = None,
    ) -> list[Finding]: ...


class Registry:
    """Explicit registration of trusted local Python code; no downloads or entry-point auto-loading."""

    def __init__(self) -> None:
        self.plugins: dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        if plugin.active or plugin.network:
            raise OberhauError("Only trusted offline plugins are supported in this release")
        if plugin.identifier in self.plugins:
            raise OberhauError("Duplicate plugin identifier")
        self.plugins[plugin.identifier] = plugin
