# Verification

`.github/workflows/tests.yml` runs these regressions on GitHub-hosted Windows with Python 3.12
for `main`, `testes` and pull requests. External scanners and Ollama are optional and are not
installed in that job; adapter contracts use synthetic fixtures, as described below.

Use the local Python environment:

```powershell
.\.venv\Scripts\ruff.exe check src tests examples
.\.venv\Scripts\ruff.exe format --check src tests examples
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.oberhau\pytest-current --cov=oberhau --cov-report=term-missing --cov-report=json:coverage.json
.\.venv\Scripts\python.exe scripts\smoke_desktop.py
```

`--basetemp` points pytest at the workspace because the Codex Windows sandbox temp area can deny
file creation/SQLite access. Use a new dedicated directory for each parallel test run; pytest may
clear that directory. GUI smoke uses Qt offscreen and actual persisted records and background scans.

The initial suite covers real ingestion/scanning/normalization/correlation/investigation/laboratory/
report/export, negative controls, review requirements, repeat scans, changed snapshots, process
locks, cancellation, missing binaries, malformed output, path/ZIP boundaries, Ollama failure/schema,
secret redaction, transactional migration rollback, backup restore, offline schedules and a plugin.
Parser fixtures for absent scanners are explicitly synthetic test inputs, never production results.

The bundled Python fixture produces six warnings and the corrected control produces zero. These
are regression expectations for intentionally small fixtures, not a measured field precision score.
The local SQL replay records two vulnerable-query rows and zero parameterized-control rows.

Semgrep 1.180.0 was executed on the managed fixture with explicit bundled rules; one real eval alert
was correlated with the matching builtin finding. Native core execution required leaving the Codex
socket-restricted sandbox; no external target was involved. Gitleaks/OSV/Trivy were not available
for live scanner verification, and Ollama API was unavailable for live inference.

Coverage and exact verified commands/results are recorded in WORKLOG.md. UI coverage is lower than
core coverage; tests do not claim every dialog, scanner version or vulnerability class is covered.
