@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo Run scripts\Setup.ps1 first. See INSTALLATION.md.
  pause
  exit /b 1
)
set "PYTHONPATH=%~dp0src"
set "PATH=%~dp0.venv\Scripts;%PATH%"
start "" ".venv\Scripts\pythonw.exe" -m oberhau gui
