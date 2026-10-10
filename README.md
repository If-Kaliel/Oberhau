# OBERHAU

**Security Research Workbench · Windows · local-first · no paid runtime services**

**1.0.0** is a native desktop and CLI for authorized offline source investigation, with a bounded
release scope described in [RELEASE_1_0.md](RELEASE_1_0.md). Selected framework syntax profiles,
evidence graphs and authorization review hypotheses support human investigation. The Research page
has filterable rows, expandable evidence, verified source navigation and optional technical JSON.
Research storage limits and conservative cache cleanup preserve completed history and human decisions.
External evaluation records both detected and missed cases; it does not establish field precision.
The complete Directive 002 remains broader than 1.0. Development stays on `testes`; `main` and
the previous 0.4.0 release are preserved until a separate merge/publication.

Select **Pesquisa contextual / Research** or use `scan ID --profile research`.
Import a folder, source file, ZIP or public HTTPS Git repository; scan a managed snapshot; investigate normalized warnings;
record human decisions; reproduce the bundled SQL laboratory; generate and export review drafts.

Download the portable Windows ZIP from [Releases](https://github.com/If-Kaliel/Oberhau/releases),
extract the entire folder and open **Oberhau.exe**; Python is included. For source installation,
follow [INSTALLATION.md](INSTALLATION.md), then open **Launch-Oberhau.cmd**.
Portuguese quick start: [GUIA_RAPIDO_PT_BR.md](GUIA_RAPIDO_PT_BR.md).

Public repository: [If-Kaliel/Oberhau](https://github.com/If-Kaliel/Oberhau).
`main` holds the validated release; `testes` is for changes under validation. GitHub Actions runs
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
| Native PySide6 dark desktop, SVG emblem, 12 pages | Implemented; navigation and worker smoke tested |
| Projects, policy records, local/ZIP/Git snapshots, SHA-256 provenance | Implemented; raw Git blobs verified without checkout/hooks; refresh and redacted file comparison |
| Python AST + literal secrets + debug/privilege heuristics | Implemented; six fixture alerts, zero on corrected control |
| Semgrep CE, ten explicit bundled rules | Real Windows execution verified; JS/TS request flows, Servlet/ASP.NET SQL; eight positive alerts and zero corrected-control alerts |
| Gitleaks / OSV v2 / Trivy | Real Windows fixture scans verified; explicit checksum-verified installation and public cache refresh |
| Historical observations, conservative correlation, human reviews | Explicit advisory aliases correlate by manifest/package/ecosystem/version; scanner runs persist even with zero warnings |
| Portable research backup/recovery | SQLite plus current/historical source snapshots; checksums, new-directory restore and relocated evidence paths |
| Source investigation | Redacted excerpt, checksum check, bounded Python assignment slice and same-name caller references, history and review questions |
| Qwen JSON drafts | Actual qwen3.5:4b inference verified; schema/claim guards, cancellable HTTP, Windows process coordination, bounded JSON and fallback |
| Reports | Editable history and evidence-completeness checks; Markdown / escaped HTML / JSON / SARIF exports |
| Laboratory | Bundled SQL plus two trusted synthetic loopback HTTP recipes; imported applications are never executed |
| Contextual investigation | Selected Next.js/Spring/ASP.NET syntax; provisional hypotheses, evidence tables, source verification and explicit coverage gaps |
| Research retention | Configurable logical cache/history/run limits; preview and cleanup of unreferenced cache; no automatic deletion of evidence or review decisions |
| In-app offline schedules | Persisted intervals, opt-in, run while GUI is open and idle |
| Metrics and manual rewards/time | Persisted counts; no bounty predictions |
| Portable Windows build / resource diagnostics | GUI + CLI EXEs, dynamic Qt, complete upstream sources/notices; actual RAM/NVIDIA probes |
| External active testing | Unavailable; blocked in engine boundary |
| Localization | English / pt-BR navigation and common controls; detailed technical messages remain English |

This is a scoped investigation release; broader master-specification capabilities remain on the roadmap.
[ROADMAP.md](ROADMAP.md) records remaining capabilities and [WORKLOG.md](WORKLOG.md) records verification.
Static warnings never prove reachability, exploitability, novelty or bounty eligibility.

Documentation: [architecture](ARCHITECTURE.md), [user guide](USER_GUIDE.md), [scanners](SCANNERS.md),
[Ollama](OLLAMA.md), [security](SECURITY_MODEL.md), [plugins](PLUGIN_DEVELOPMENT.md),
[backup/recovery](BACKUP.md), [testing](TESTING.md), [troubleshooting](TROUBLESHOOTING.md), [changelog](CHANGELOG.md).
