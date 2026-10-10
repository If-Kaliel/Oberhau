# Verification

Directive 002 adds contextual, assistant and validation/GUI regressions: framework positive/negative
controls, intermediate/constant arguments, cache/history/backup, comment metadata, Python branch/
sanitizer uncertainty, cross-file report integrity, typed-query/citation rejection/fallback and Qt
workers. Local HTTP tests use only owned loopback sockets. Exact results are in WORKLOG.md.

Independent detection evaluation: `oberhau benchmark`, identified by the unchanged
`assets/research_benchmark.json` hash. It retains every expected/detected/missed signal and resource
scope. The unit test checks measurement accounting rather than forcing perfect detection. The 12
original synthetic cases do not establish an independently curated production detection rate.

`.github/workflows/tests.yml` runs these regressions on GitHub-hosted Windows with Python 3.12
for `main`, `testes` and pull requests. External scanners and Ollama are optional and are not
installed in that job; adapter contracts use synthetic fixtures, as described below.

Use the local Python environment:

```powershell
.\.venv\Scripts\ruff.exe check src tests examples scripts packaging
.\.venv\Scripts\ruff.exe format --check src tests examples scripts packaging
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

Research backup tests restore to a different data home after making the original unavailable,
including historical snapshots, notes/reports/laboratory records, empty directories and large
observation history. They exercise byte corruption, unsafe ZIP members, edited SQLite schemas,
foreign-key failures, missing inventory, cancellation, storage exclusion and destination races.
The Qt recovery regression performs real backup/restore jobs and opens the recovered research;
only its interactive file-picker choices are supplied by the test.

The bundled Python fixture produces six warnings and the corrected control produces zero. These
are regression expectations for intentionally small fixtures, not a measured field precision score.
The local SQL replay records two vulnerable-query rows and zero parameterized-control rows.

Semgrep 1.180.0 was executed on the managed fixture with explicit bundled rules; one real eval alert
was correlated with the matching builtin finding. Native core execution required leaving the Codex
socket-restricted sandbox; no external target was involved. Gitleaks 8.30.1, OSV 2.6.0 and Trivy
0.75.0 also passed real Windows fixture scans with negative controls. Ollama qwen3.5:4b live inference was verified separately, including preservation of evidence/review state.

Real optional scanner tests never download tools or feeds implicitly. Prepare them first as
described in SCANNERS.md, then opt in:

```powershell
$env:OBERHAU_INTEGRATION_HOME = (Resolve-Path .oberhau\verified).Path
$env:PATH = (Resolve-Path .venv\Scripts).Path + ";" + $env:PATH # Installed Semgrep
.\.venv\Scripts\python.exe -m pytest -q tests/test_live_scanners.py --basetemp=.oberhau\pytest-live
Remove-Item Env:OBERHAU_INTEGRATION_HOME
```

The dependency negative control is Django 6.1.2, verified against the official download page on
2026-10-10. No advisory match in these cached feeds is a bounded regression result. New advisories
may intentionally cause that test to fail and require reviewing the control version. Empty OSV
manifests cause exit 128 and are treated as lack of coverage, not successful analysis.

Coverage and exact verified commands/results are recorded in WORKLOG.md. UI coverage is lower than
core coverage; tests do not claim every dialog, scanner version or vulnerability class is covered.

Live Qwen tests opt in with `OBERHAU_LIVE_QWEN=1` and `pytest tests/test_live_ollama.py`; they
require the already installed model and running local Ollama, and download nothing. Deterministic
tests cover JSON/UTF-8 budgets, unknown CVE/URL rejection, cross-process model arbitration,
queue cancellation and a stalled Connection: close HTTP body. Native Git fixtures use generated
local repositories with a test-only transport override; production imports accept HTTPS only.
Tests preserve raw blobs despite attributes/inherited hostile configuration, validate update/diff/
portable recovery and prove scripts never execute. Actual public repository acquisition was also
checked manually. Frozen CLI/native GUI tests and library-source manifest checks are described
in WINDOWS_BUILD.md. Optional tests and real observations are distinguished in WORKLOG.md.
