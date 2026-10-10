# Worklog — 2026-10-10

## Session objective and delivered state

User supplied the Oberhau Master Development Specification and requested actual iterative
implementation in this empty Git workspace. Delivered 0.1.0: a usable, tested offline research
vertical slice. The entire master specification is not complete; ROADMAP.md is the continuation
contract, and unsupported capabilities are not presented as operational.

Implemented native Windows PySide6 GUI/CLI with a shared engine; original SVG sword/skull identity;
SQLite WAL and migrations v1/v2; program policy records; local folder/file/ZIP snapshots, hashes and
refresh; bounded scanner orchestration and OS project locks; builtin Python AST/secret/config checks;
Semgrep/Gitleaks/OSV/Trivy adapters; conservative correlation with separate original observations;
investigation excerpts/integrity/history; human decisions and reopening on changed source hashes;
checksum-matched disposable SQL reproduction/regression; editable deterministic/local-Qwen draft
reporting and Markdown/HTML/JSON/SARIF exports; backups; opt-in in-app offline schedules; persisted
metrics and manually entered returns; dependency diagnostics; rotating logs; trusted plugin example;
first-run setup; English/pt-BR common controls; launch/setup scripts; pinned environment; Python wheel.

## Environment and verified dependencies

- Windows 11 10.0.26200, 12 logical CPU threads, Git installed.
- `python` resolved to the unusable Windows Store alias; `py` referenced absent C:\Python314\python.exe.
- Used the available Codex bundled Python 3.12.14 to create this workspace's `.venv`.
- Bundled runtime lacked ensurepip. Created venv, installed dependencies through base pip's
  `--python .venv\Scripts\python.exe`, then installed pip itself in the project environment.
- Verified PySide6 Essentials 6.10.2, Pydantic 2.12.5, pytest 9.0.2, pytest-cov 7.0.0,
  Ruff 0.15.6, Semgrep CE 1.180.0, setuptools 82.0.1. Full freeze: requirements-lock-windows.txt.
- Project installed editable; `oberhau.exe` entry point executed successfully.
- Ollama executable detected; its loopback API refused connection. Qwen inference remains unverified.
- Gitleaks, OSV-Scanner, Trivy, ZAP, Nuclei, CodeQL absent. No target-directed external scan occurred.

## Commands and results

Commands run from this workspace (using the working .venv interpreter after setup):

```powershell
.\.venv\Scripts\ruff.exe check src tests examples scripts --fix
.\.venv\Scripts\ruff.exe format src tests examples scripts
.\.venv\Scripts\python.exe -m compileall -q src
.\.venv\Scripts\python.exe -m oberhau --home .oberhau\verified demo
.\.venv\Scripts\python.exe -m oberhau --home .oberhau\verified scan 1 --profile standard
.\.venv\Scripts\python.exe -m oberhau --home .oberhau\verified diagnostics
.\scripts\Run-CLI.ps1 --home .oberhau\verified metrics
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.oberhau\pytest-final --cov=oberhau --cov-report=term-missing --cov-report=json:coverage.json
.\.venv\Scripts\ruff.exe check src tests examples scripts
.\.venv\Scripts\ruff.exe format --check src tests examples scripts
.\.venv\Scripts\python.exe scripts\smoke_desktop.py
.\.venv\Scripts\python.exe scripts\smoke_desktop.py --native
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip freeze --exclude-editable
.\.venv\Scripts\python.exe -m pip wheel . --no-deps --no-build-isolation --wheel-dir artifacts
git diff --check
```

- Final full suite before the startup-diagnostic follow-up: **71 passed**, 36.16 s;
  **82.07% total line coverage** (1465/1785 statements covered). Engine 95%, DB 97%, builtin scanner
  94%, laboratory 97%, CLI 97%, GUI 70%. Source redaction now withholds private-key material before
  selecting excerpts while preserving original line numbers. Metrics include per-scanner observations,
  reviewed false positives, severity/confidence distributions and manual outcomes.
- Targeted CLI/pipeline suite after metrics additions: **23 passed**, 20.64 s.
- First-run demonstration now defers automatic diagnostics until its worker finishes; this small
  final startup fix passed its GUI regression again: **1 passed**, 7.83 s. Ruff and formatting passed.
- Final wheel rebuilt after these corrections: 49,851 bytes; SHA-256
  `5d6bc7e33d92169be103457f4740e0d67ae2cf6abd1c2650aa7c9f7eb34081bb`.
- Ruff check and formatting check passed. Source compiled successfully.
- Real fixture scan: six builtin warnings; zero warnings on fixed.py.
- Real native Windows Semgrep scan: one eval alert; explicitly equivalent builtin/Semgrep alerts
  consolidate into one finding while retaining both scanner observations. Standard scan completed.
- Lab disposable SQLite observed 2 rows for the vulnerable query, 0 for the corrected query.
- GUI smoke navigated all 11 pages, ran a real shared-engine scan in QThread, investigated a finding,
  generated a real report and closed cleanly. Native Windows smoke also launched/rendered/closed.
- Visually inspected artifacts/desktop-overview.png and artifacts/desktop-investigations.png. These
  use a separate, visibly labeled demonstration database and are excluded from Git.
- Built artifacts/oberhau-0.1.0-py3-none-any.whl. Packaging is a Python wheel, not a standalone EXE.

## Failures encountered and resolution

- Initial dependency downloads failed DNS in sandbox; installation succeeded with authorized
  network access, confined to this virtual environment.
- First venv creation failed ensurepip; base pip --python installed the missing environment tooling.
- Initial GUI source had a missing list-comprehension bracket; corrected before compile/UI tests.
- Semgrep execution failed socketpair EACCES inside the Codex sandbox. The exact local fixture scan
  succeeded outside socket restrictions; no change to scope policy or external target access.
- Pytest default sandbox temporary path caused setup errors; reran with workspace --basetemp.
  A wheel rebuild also hit sandbox temporary-directory permissions; rebuilding outside that
  restriction succeeded. These are host sandbox limitations, not outstanding product failures.
- Qt offscreen fonts rendered empty glyphs. Added explicit Segoe UI registration only when Qt has
  no font database, then visually verified offscreen and normal Windows rendering.
- Extended test suite initially had 69 pass / 1 fail because source-file refresh was unsupported.
  Extended refresh to existing local files; full suite rerun passed all 70.
- No unresolved failing test at the end of the full suite. Ollama and missing scanners are explicit
  environmental limitations; they do not block Quick Scan or deterministic reports.

## Known limits / exact next steps

1. Verify missing optional adapters against actual signed/checksummed Windows binaries and known
   offline advisory caches; test Django fixture dependency matching and fixed-version evidence.
2. Build complete backup/recovery of source snapshots with portable paths and retention controls.
3. Strengthen reparse/TOCTOU boundaries and trusted executable configuration; add OS quotas.
4. Add safe authorized Git clone/update/history comparisons and explicit trusted rule management.
5. Extend framework coverage, semantic fingerprints, source-to-sink investigation and caching.
6. Start existing Ollama manually and live-test qwen3.5:4b JSON drafts, hallucination checks,
   cancellation and unload behavior. Do not claim this was already verified.
7. Add model-aware token accounting, general safe local lab recipes and scanner SDK process isolation.
8. Complete localization, visual analytic filters/charts, policy metadata and packaged Windows release.

Other limitations: active executor absent; no DNS/redirect testing enforcement; plugins are trusted
in-process code; no generalized reachability/novelty proof; no CodeQL/ZAP/Nuclei/Docker integration;
one GUI research job at a time; schedules analyze snapshots and do not update source automatically;
no complete RAM/CPU/GPU quotas; scanner argument/network control is not an OS network sandbox.

All working source, tests and docs are preserved. Normal user data stays empty until imports are
chosen. Development/demo data and screenshots are isolated under .oberhau/ and artifacts/.

Original user specification is preserved as MASTER_SPECIFICATION.md. Work is saved on
`codex/desktop-foundation` with a focused implementation commit. No push or external publication.
