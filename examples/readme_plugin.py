"""Trusted offline example plugin: reports missing security-contact documentation."""

from collections.abc import Callable
from pathlib import Path
from threading import Event

from oberhau.core import Finding, Limits


class SecurityContactPlugin:
    identifier = "security-contact"
    version = "1.0.0"
    license = "MIT"
    network = False
    active = False
    categories = ["documentation"]

    def scan(
        self,
        root: Path,
        paths: list[str],
        cancel: Event,
        limits: Limits,
        progress: Callable[[str], None],
        categories: list[str] | None = None,
    ) -> list[Finding]:
        if cancel.is_set() or any(Path(p).name.lower() == "security.md" for p in paths):
            return []
        readme = next((p for p in paths if Path(p).name.lower() == "readme.md"), None)
        if readme is None:
            return []
        progress("security-contact: missing SECURITY.md")
        return [
            Finding(
                scanner=self.identifier,
                rule="security-contact-document",
                category="documentation",
                title="No SECURITY.md in project index",
                path=readme,
                severity="informative",
                confidence=1,
                explanation="Documentation observation; not a vulnerability.",
            )
        ]
