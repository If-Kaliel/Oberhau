"""Build a Windows x64 onedir release with complete Qt library sources and notices."""

import argparse
import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oberhau import __version__  # noqa: E402

QT_BASE = "https://download.qt.io/archive/qt/6.10/6.10.2/submodules/"
SOURCES = {
    "qtbase-everywhere-src-6.10.2.tar.xz": (
        QT_BASE,
        "aeb78d29291a2b5fd53cb55950f8f5065b4978c25fb1d77f627d695ab9adf21e",
    ),
    "qtsvg-everywhere-src-6.10.2.tar.xz": (
        QT_BASE,
        "f07ff80f38caf235187200345392ca7479445ddf49a36c3694cd52a735dad6e1",
    ),
    "pyside-setup-everywhere-src-6.10.2.tar.xz": (
        "https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.10.2-src/",
        "05eec38bb71bffff8860786e3c0766cc4b86affc72439bd246c54889bdcb7400",
    ),
}


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def library_sources():
    cache = ROOT / ".oberhau/release-sources"
    cache.mkdir(parents=True, exist_ok=True)
    for name, (base, expected) in SOURCES.items():
        target = cache / name
        if not target.is_file():
            partial = target.with_suffix(".download")
            print(f"Downloading official library source: {name}", flush=True)
            try:
                with (
                    urllib.request.urlopen(base + name, timeout=60) as response,
                    partial.open("wb") as output,
                ):
                    total = 0
                    while chunk := response.read(1_000_000):
                        total += len(chunk)
                        if total > 150_000_000:
                            raise RuntimeError("Library source exceeded size limit")
                        output.write(chunk)
                if checksum(partial) != expected:
                    raise RuntimeError("Official library source checksum mismatch")
                partial.replace(target)
            finally:
                partial.unlink(missing_ok=True)
        if checksum(target) != expected:
            raise RuntimeError(f"Invalid cached library source: {name}")
        yield target


def notices(bundle, archives):
    directory = bundle / "licenses"
    directory.mkdir(exist_ok=True)
    shutil.copyfile(Path(sys.base_prefix) / "LICENSE.txt", directory / "Python-LICENSE.txt")
    for name in (
        "pydantic",
        "pydantic_core",
        "annotated_types",
        "typing_extensions",
        "typing_inspection",
    ):
        distribution = importlib.metadata.distribution(name)
        for file in distribution.files:
            if "/licenses/" in str(file).replace("\\", "/"):
                target = directory / name / Path(str(file)).name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(distribution.locate_file(file), target)
    for archive in archives:
        # Copy only regular notice files to a confined hierarchy; never extract source trees.
        with tarfile.open(archive, "r:xz") as source:
            for member in source:
                relative = PurePosixPath(member.name)
                name = relative.name.lower()
                if not member.isfile() or not (
                    name.startswith(("license", "copying", "copyright", "notice"))
                    or "LICENSES" in relative.parts
                ):
                    continue
                if relative.is_absolute() or ".." in relative.parts or member.size > 4_000_000:
                    raise RuntimeError("Invalid library notice")
                target = directory / "Qt" / Path(*relative.parts)
                if not target.resolve().is_relative_to(directory.resolve()):
                    raise RuntimeError("Library notice escapes output")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as content, target.open("wb") as output:
                    shutil.copyfileobj(content, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-freeze",
        action="store_true",
        help="Refresh notices/docs/archive after an existing build",
    )
    args = parser.parse_args()
    if platform.system() != "Windows" or platform.machine().upper() not in {"AMD64", "X86_64"}:
        raise RuntimeError("Release build requires Windows x64")
    bundle = ROOT / "dist/Oberhau"
    if not args.skip_freeze:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--distpath",
                str(ROOT / "dist"),
                "--workpath",
                str(ROOT / "build/frozen"),
                str(ROOT / "packaging/Oberhau.spec"),
            ],
            cwd=ROOT,
            check=True,
        )
    if not (bundle / "Oberhau.exe").is_file() or not (bundle / "oberhau-cli.exe").is_file():
        raise RuntimeError("Build both entry points before packaging")
    archives = list(library_sources())
    included = bundle / "sources"
    included.mkdir(exist_ok=True)
    for archive in archives:
        shutil.copyfile(archive, included / archive.name)
    notices(bundle, archives)
    for document in [ROOT / "LICENSE", *ROOT.glob("*.md")]:
        shutil.copyfile(document, bundle / document.name)
    files = {
        path.relative_to(bundle).as_posix(): {
            "sha256": checksum(path),
            "bytes": path.stat().st_size,
        }
        for path in sorted(bundle.rglob("*"))
        if path.is_file() and path.name != "MANIFEST.json"
    }
    (bundle / "MANIFEST.json").write_text(
        json.dumps(
            {
                "version": __version__,
                "platform": "Windows x64",
                "files": files,
                "qt_library_sources": {name: checksum(included / name) for name in SOURCES},
                "build": {
                    "python": platform.python_version(),
                    "pyinstaller": importlib.metadata.version("pyinstaller"),
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    output = artifacts / f"Oberhau-{__version__}-windows-x64.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target:
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                target.write(path, "Oberhau/" + path.relative_to(bundle).as_posix())
    output.with_suffix(".zip.sha256").write_text(
        f"{checksum(output)}  {output.name}\n", encoding="ascii"
    )
    print(
        json.dumps(
            {"archive": str(output), "bytes": output.stat().st_size, "sha256": checksum(output)},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
