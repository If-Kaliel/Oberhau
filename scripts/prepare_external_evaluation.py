"""Explicitly acquire public, revision-pinned evaluation data. Never execute it."""

import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / ".oberhau/external-evaluation"
SOURCES = {
    "bandit": (
        "PyCQA/bandit",
        "68ebe11ef79263be27ec223184b94a4fc394a622",
        [
            "LICENSE",
            "examples/sql_statements.py",
            "examples/subprocess_shell.py",
            "examples/exec.py",
            "tests/functional/test_functional.py",
        ],
    ),
    "webgoat": (
        "WebGoat/WebGoat",
        "044948d057b249735be2bfc14eccc9e3dc2eac34",
        [
            "LICENSE.txt",
            "src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java",
            "src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java",
            "src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java",
        ],
    ),
    "prisma": (
        "prisma/prisma-examples",
        "caa902a819be2e8fe1e0b0ec2f543e9220cf69cc",
        ["LICENSE", "orm/nextjs/README.md"],
    ),
}


def fetch(url):
    with urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "Oberhau-release-evaluation"}),
        timeout=30,
    ) as response:
        data = response.read(5_000_001)
    if len(data) > 5_000_000:
        raise RuntimeError("External evaluation source exceeds download budget")
    return data


def main():
    records = []
    manifest_path = ROOT / "evaluation/external-sources.json"
    expected = (
        {
            (f["project"], f["path"]): f["sha256"]
            for f in json.loads(manifest_path.read_text())["files"]
        }
        if manifest_path.exists()
        else {}
    )
    for name, (repository, revision, paths) in SOURCES.items():
        if name == "prisma":
            tree = json.loads(
                fetch(f"https://api.github.com/repos/{repository}/git/trees/{revision}?recursive=1")
            )
            paths = sorted(
                set(
                    paths
                    + [
                        item["path"]
                        for item in tree["tree"]
                        if item["path"].startswith("orm/nextjs/")
                        and item["path"].endswith((".ts", ".tsx", ".json", ".prisma"))
                    ]
                )
            )
        for path in paths:
            url = f"https://raw.githubusercontent.com/{repository}/{revision}/{path}"
            data = fetch(url)
            digest = hashlib.sha256(data).hexdigest()
            if expected and expected.get((name, path)) != digest:
                raise RuntimeError(
                    "Pinned external evaluation checksum changed; existing manifest is preserved"
                )
            target = DESTINATION / name / path
            if not target.resolve().is_relative_to(DESTINATION.resolve()):
                raise RuntimeError("External evaluation path escapes its directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            records.append(
                {
                    "project": name,
                    "repository": repository,
                    "revision": revision,
                    "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "url": url,
                }
            )
    target = ROOT / "evaluation/external-sources.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "method": "Original upstream bytes. Explicit opt-in download; no install, imports, application execution or target requests.",
                "files": records,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        json.dumps({"files": len(records), "directory": str(DESTINATION), "manifest": str(target)})
    )


if __name__ == "__main__":
    main()
