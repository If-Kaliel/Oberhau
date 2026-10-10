param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $projectRoot 'src'
$env:PATH = (Join-Path $projectRoot '.venv\Scripts') + ';' + $env:PATH
& (Join-Path $projectRoot '.venv\Scripts\python.exe') -m oberhau @Arguments
exit $LASTEXITCODE
