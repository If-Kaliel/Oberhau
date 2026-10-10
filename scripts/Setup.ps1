param([string]$Python = 'py', [switch]$Scanners)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
if ($Python -eq 'py') {
    & py -3.12 -m venv .venv
} else {
    & $Python -m venv .venv
}
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ is required. Pass -Python with a working interpreter path.' }
& '.\.venv\Scripts\python.exe' -m pip install -e '.[dev]'
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
if ($Scanners) {
    & '.\.venv\Scripts\python.exe' -m pip install 'semgrep==1.180.0'
    if ($LASTEXITCODE -ne 0) { throw 'Optional Semgrep installation failed.' }
}
Write-Host 'Ready. Open Launch-Oberhau.cmd. No Windows startup service was installed.'
