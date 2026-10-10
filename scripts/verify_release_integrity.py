"""Verify the final archive, wheel, documents and embedded application code."""

import hashlib
import json
import sys
import types
import zipfile
from pathlib import Path

from PyInstaller.archive.readers import CArchiveReader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oberhau import __version__  # noqa: E402


def code_signature(code):
    def value(item):
        if isinstance(item, types.CodeType):
            return code_signature(item)
        if isinstance(item, (tuple, list)):
            return [value(c) for c in item]
        if isinstance(item, frozenset):
            return sorted(repr(c) for c in item)
        return repr(item)

    return [
        code.co_code.hex(),
        code.co_exceptiontable.hex(),
        code.co_stacksize,
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_flags,
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
        [value(c) for c in code.co_consts],
    ]


def main():
    archive = ROOT / "artifacts" / f"Oberhau-{__version__}-windows-x64.zip"
    wheel = ROOT / "artifacts" / f"oberhau-{__version__}-py3-none-any.whl"
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert archive_hash == archive.with_suffix(".zip.sha256").read_text().split()[0]
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.testzip() is None
        manifest = json.loads(bundle.read("Oberhau/MANIFEST.json"))
        assert manifest["version"] == __version__
        for path, expected in manifest["files"].items():
            data = bundle.read("Oberhau/" + path)
            assert len(data) == expected["bytes"]
            assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        for path in [*ROOT.glob("*.md"), *(ROOT / "evaluation").glob("*.json")]:
            relative = path.relative_to(ROOT).as_posix()
            assert bundle.read("Oberhau/" + relative) == path.read_bytes()
        assert len(manifest["qt_library_sources"]) == 3
        for name, digest in manifest["qt_library_sources"].items():
            assert hashlib.sha256(bundle.read("Oberhau/sources/" + name)).hexdigest() == digest
    modules = []
    archives = {
        binary: CArchiveReader(str(ROOT / "dist/Oberhau" / binary)).open_embedded_archive("PYZ.pyz")
        for binary in ("Oberhau.exe", "oberhau-cli.exe")
    }
    with zipfile.ZipFile(wheel) as packaged:
        assert packaged.testzip() is None
        for path in sorted((ROOT / "src/oberhau").rglob("*.py")):
            relative = path.relative_to(ROOT / "src")
            if "assets" in relative.parts or path.name == "__main__.py":
                continue
            assert packaged.read(relative.as_posix()) == path.read_bytes()
            parts = list(relative.with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
            name = ".".join(parts)
            for embedded in archives.values():
                built = embedded.extract(name)
                expected = compile(
                    path.read_text(encoding="utf-8"),
                    built.co_filename,
                    "exec",
                    dont_inherit=True,
                    optimize=0,
                )
                assert code_signature(built) == code_signature(expected), (
                    f"Embedded module differs: {name}"
                )
            modules.append(name)
    result = {
        "version": __version__,
        "archive": {
            "file": archive.name,
            "bytes": archive.stat().st_size,
            "sha256": archive_hash,
            "manifest_files": len(manifest["files"]),
        },
        "wheel": {
            "file": wheel.name,
            "bytes": wheel.stat().st_size,
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        },
        "embedded_modules_checked_in_both_executables": modules,
        "documents_and_evaluation_match": True,
        "qt_source_archives_verified": 3,
        "limits": "Code signatures compare instructions/constants/arguments, excluding file paths and line tables. This verifies included application code, not every third-party dependency or OS compatibility.",
    }
    target = ROOT / "artifacts/oberhau-1.0-integrity.json"
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
