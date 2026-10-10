# Windows installation

In this checkout, `.venv` is prepared with Python 3.12.14, PySide6 Essentials 6.10.2,
Pydantic 2.12.5, testing tools and Semgrep CE 1.180.0. Open `Launch-Oberhau.cmd`.
The local virtual environment uses the available Codex bundled interpreter; do not move it to
another computer or remove its base runtime. Portable application packaging remains pending.

For a regular installation, install a complete Python 3.12+ from the official Python distribution
and Git if repository commit metadata is wanted. Then run PowerShell in this directory:

```powershell
.\scripts\Setup.ps1
# If the Python launcher points to an invalid installation:
.\scripts\Setup.ps1 -Python 'C:\path\to\working\python.exe'
# Optional real Semgrep integration:
.\scripts\Setup.ps1 -Scanners
.\Launch-Oberhau.cmd
```

Alternatively:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m pip install semgrep==1.180.0
.\scripts\Run-CLI.ps1 diagnostics
```

Only initial dependency installation needs internet. No paid APIs, cloud accounts, containers,
WSL, administrator installation or Windows startup service are required. Optional advisory
scanners need explicitly prepared caches; ordinary scans never refresh them automatically.

`requirements-lock-windows.txt` captures the verified development environment, including optional
Semgrep dependencies. It is a Windows/Python 3.12 environment snapshot, not a cross-platform lock.
For source installs, runtime direct dependencies are pinned in pyproject.toml.

Core dependencies use Pydantic (MIT) and dynamically loaded PySide6/Qt Essentials under their
open-source terms. See [THIRD_PARTY.md](THIRD_PARTY.md) before redistributing binaries.
