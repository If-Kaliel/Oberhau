"""Security review deltas for retained local snapshots; no remote polling."""

from __future__ import annotations

from pathlib import PurePosixPath


def changes(previous: dict, current: dict, before: dict, after: dict) -> dict:
    modified = sorted(
        path for path in before.keys() | after.keys() if before.get(path) != after.get(path)
    )

    def controls(result):
        return {
            (node["path"], node["label"])
            for node in result.get("graph", {}).get("nodes", [])
            if node["kind"] == "control"
        }

    old_controls, new_controls = controls(previous), controls(current)
    dependency_names = {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "pom.xml",
        "build.gradle",
        "gradle.lockfile",
        "packages.lock.json",
        "requirements.txt",
        "poetry.lock",
        "pyproject.toml",
    }
    sensitive = {
        n["path"]
        for result in (previous, current)
        for n in result.get("graph", {}).get("nodes", [])
        if n["kind"] in {"endpoint", "operation", "control"}
    }
    return {
        "changed_files": modified,
        "sensitive_files": [p for p in modified if p in sensitive],
        "controls_added": [
            {"path": p, "control": label} for p, label in sorted(new_controls - old_controls)
        ],
        "controls_removed": [
            {"path": p, "control": label} for p, label in sorted(old_controls - new_controls)
        ],
        "dependency_files": [
            p
            for p in modified
            if PurePosixPath(p).name in dependency_names or PurePosixPath(p).suffix == ".csproj"
        ],
        "limitations": [
            "Control changes are syntax observations, not proof of a security fix or regression",
            "Dependency files are identified; package/advisory matching remains the responsibility of existing offline scanners",
            "Only retained local snapshot comparisons; source refresh and any remote acquisition remain explicit",
        ],
    }
