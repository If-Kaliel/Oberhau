# Portable Windows 11 x64 distribution

The release ZIP contains **Oberhau.exe** (native desktop) and **oberhau-cli.exe**
(console commands) with a shared Python/Qt runtime. Extract the entire `Oberhau` folder,
then double-click Oberhau.exe. Python is not required on the receiving computer.
This is a portable application directory; research data defaults to
`%LOCALAPPDATA%\Oberhau` and moves through research backup/recovery separately.

```powershell
.\oberhau-cli.exe --home 'C:\Research\Oberhau' demo
.\Oberhau.exe --home 'C:\Research\Oberhau'
```

Git imports require a separately installed Git. Optional scanners, advisory caches and
Ollama/Qwen are separate installations. Quick scans, reports and recovery work without them.
No administrator installation, registry changes or startup service is required. The executables
are unsigned; published SHA-256 files verify the downloaded release against its listed checksum.
Hash verification does not replace publisher identity or an Authenticode signature.

## Rebuild

Use Windows x64, Python 3.12 and the project virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e '.[dev,build]'
.\.venv\Scripts\python.exe scripts\build_windows.py
```

The build script compiles two entry points from `packaging/Oberhau.spec` with PyInstaller 6.22.3,
downloads three fixed-checksum official Qt/PySide source archives, gathers their notices and
the Python dependency licenses, and writes `artifacts/Oberhau-0.5.1-windows-x64.zip` plus `.sha256`.
The bundle includes a per-file `MANIFEST.json`. Builds are version-pinned, not bit-for-bit reproducible.
`--skip-freeze` only refreshes documents/notices and the ZIP after an existing compilation; do not
use it after changing application code. Build downloads occur only during this explicit developer step.

Validate the frozen entry points with an isolated data directory:

```powershell
.\dist\Oberhau\oberhau-cli.exe --home .oberhau\packaged-cli demo
.\dist\Oberhau\Oberhau.exe --home .oberhau\packaged-gui --smoke artifacts\packaged-desktop.png
```

`--smoke` explicitly imports a labeled demonstration, runs Quick, saves a real Qt screenshot and
metrics, then exits. Use a fresh data directory for the six-finding expectation.

0.5.1 derives multi-size Windows executable icons directly from the SVG skull/sword using
`scripts/render_brand.py`. Research workers use the hidden sibling CLI entry for bounded pipes.
`--smoke-research artifacts/research.png` runs the bundled labeled contextual fixture through
the frozen GUI, checks completion/worker memory enforcement and captures its Research page.
For the broader native check, run:

```powershell
.\.venv\Scripts\python.exe scripts\verify_windows.py
```

This uses fresh owned data and a system-only PATH: frozen default-import research, worker memory
metrics, deterministic assistant, unchanged benchmark, both trusted HTTP recipes, portable
backup/restore and both native GUI smoke modes. It downloads nothing and installs no service.

## Qt source and replacement rights

PySide6 Essentials, Shiboken6, Qtbase and QtSvg 6.10.2 are unmodified dynamically loaded libraries
used under LGPLv3. The application includes a **Licenses** control. Full upstream source archives
are included in `sources/` in the same ZIP, preserving copyright and third-party notices. The
`licenses/Qt/` directory additionally includes the upstream license and copyright files, including
LGPLv3 and GPLv3. Source downloads and hashes are fixed in `scripts/build_windows.py`.

Qt DLLs and bindings remain separate under `_internal/PySide6/` and `_internal/shiboken6/`.
You may replace them with modified ABI-compatible builds, keeping the directory layout. Rebuild
the application from its public MIT source if your change needs different bindings. No signature,
receipt or DRM check restricts Qt replacement; the scanner receipt checks apply only to optional
scanner executables. Reverse engineering for debugging modifications to these libraries is permitted.
The upstream source archives contain library build scripts; Qt build configuration must match
the replacement bindings and Python ABI. The original wheels remain obtainable from PyPI.

References: [Qt LGPL obligations](https://www.qt.io/development/open-source-lgpl-obligations),
[Qt module licensing](https://doc.qt.io/qt-6/licensing.html),
[PyInstaller licensing exception](https://pyinstaller.org/en/stable/license.html).

Build search paths are restricted to the selected Python runtime and Windows system directory. The Qt codec uses the Windows 11 ICU API; unrelated ICU binaries discovered in a developer Git/PATH installation are excluded. Native EXE rendering is part of release QA.
