"""Dependency equivalence requires the same manifest, package/version and explicit alias."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import unquote, urlsplit

from oberhau.core import Finding


def dependency_scope(finding: Finding) -> str | None:
    if finding.category != "dependencies":
        return None
    package = finding.evidence.get("package", {})
    if not isinstance(package, dict):
        return None
    ecosystem = str(package.get("ecosystem", "")).lower()
    name, version = package.get("name"), package.get("version")
    purl = package.get("purl", "")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        value = urlsplit(purl).path
        kind, _, remainder = value.partition("/")
        if not ecosystem:
            ecosystem = kind.lower()
        if not version and "@" in remainder:
            version = unquote(remainder.rsplit("@", 1)[1])
    if (
        ecosystem not in {"pypi", "npm"}
        or not isinstance(name, str)
        or not isinstance(version, str)
        or not name
        or not version
    ):
        return None
    normalized = re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name.lower()
    identity = json.dumps([finding.path, ecosystem, normalized, version], separators=(",", ":"))
    return hashlib.sha256(identity.encode()).hexdigest()


def advisory_aliases(finding: Finding) -> set[str]:
    return {
        value.upper()
        for value in finding.advisories
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,199}", value)
    }
