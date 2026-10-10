# OBERHAU

**Security Research Workbench · Windows · local-first · no paid runtime services**

Oberhau 0.2.0 is a working native desktop and CLI for authorized offline source research.
Import a folder, source file or ZIP; scan a managed snapshot; investigate normalized warnings;
record human decisions; reproduce the bundled SQL laboratory; generate and export review drafts.

Follow [INSTALLATION.md](INSTALLATION.md) to prepare the project virtual environment, then
double-click **Launch-Oberhau.cmd**. Python 3.12+ is required.

Public repository: [If-Kaliel/Oberhau](https://github.com/If-Kaliel/Oberhau).
`main` holds the published baseline; `testes` is for changes under validation. GitHub Actions runs
the Windows regression suite, lint checks and wheel build for both branches and pull requests.

```powershell
.\scripts\Run-CLI.ps1 --home .oberhau\demo demo
.\scripts\Run-CLI.ps1 --home .oberhau\demo findings
.\scripts\Run-CLI.ps1 --home .oberhau\demo scan 1 --profile standard
```

The desktop opens with an empty real database. Demonstration imports are explicit and labeled.
Normal storage is `%LOCALAPPDATA%\Oberhau`; `OBERHAU_HOME` or `--home` changes it.

| Capability | Actual status |
|---|---|
| Native PySide6 dark desktop, SVG emblem, 11 pages | Implemented; navigation and worker smoke tested |
| Projects, policy records, local snapshots, ZIP safety, SHA-256 provenance | Implemented |
| Python AST + literal secrets + debug/privilege heuristics | Implemented; six fixture alerts, zero on corrected control |
| Semgrep CE, explicit bundled rules | Real Windows execution verified with 1.180.0 |
| Gitleaks / OSV v2 / Trivy | Real Windows fixture scans verified; explicit checksum-verified installation and public cache refresh |
| Historical observations, conservative correlation, human reviews | Implemented; Python eval equivalence across bundled/Semgrep rules |
| Source investigation | Redacted excerpt, checksum check, same-file related IDs, history, review questions |
| Qwen JSON drafts | Local client, schema validation, bounded context and fallback implemented; live inference not verified |
| Reports | Editable history, Markdown / escaped HTML / JSON / SARIF exports |
| Laboratory | Bundled SQL fixture only; disposable SQLite and corrected regression |
| In-app offline schedules | Persisted intervals, opt-in, run while GUI is open and idle |
| Metrics and manual rewards/time | Persisted counts; no bounty predictions |
| External active testing | Unavailable; blocked in engine boundary |
| Localization | English / pt-BR navigation and common controls; detailed technical messages remain English |

This is an initial usable release, **not completion of the full master specification**.
[ROADMAP.md](ROADMAP.md) records remaining capabilities and [WORKLOG.md](WORKLOG.md) records verification.
Static warnings never prove reachability, exploitability, novelty or bounty eligibility.

Documentation: [architecture](ARCHITECTURE.md), [user guide](USER_GUIDE.md), [scanners](SCANNERS.md),
[Ollama](OLLAMA.md), [security](SECURITY_MODEL.md), [plugins](PLUGIN_DEVELOPMENT.md),
[testing](TESTING.md), [troubleshooting](TROUBLESHOOTING.md), [changelog](CHANGELOG.md).
