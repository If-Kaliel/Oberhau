# Windows installation

Install a complete Python 3.12+ from the official Python distribution
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
Optional scanners can be installed from the Scanner page or the commands in [SCANNERS.md](SCANNERS.md).
They are stored in the selected data directory and are not included in Git or in the Python wheel.
Portable EXE packaging remains pending; a virtual environment cannot be moved between computers.

`requirements-lock-windows.txt` captures the verified development environment, including optional
Semgrep dependencies. It is a Windows/Python 3.12 environment snapshot, not a cross-platform lock.
For source installs, runtime direct dependencies are pinned in pyproject.toml.

Core dependencies use Pydantic (MIT) and dynamically loaded PySide6/Qt Essentials under their
open-source terms. See [THIRD_PARTY.md](THIRD_PARTY.md) before redistributing binaries.
