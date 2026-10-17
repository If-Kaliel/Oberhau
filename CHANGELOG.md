# Changelog

## Unreleased

- Parallel scanner jobs no longer race when saving equivalent findings: `save_finding` takes the SQLite write lock before its existence check. Previously, builtin/Semgrep equivalent rules could fail the second scanner run with a UNIQUE violation and lose its remaining findings, and concurrent OSV/Trivy advisories could be stored as duplicates instead of being correlated.
- Wrongly typed nested scanner JSON is reported as malformed output instead of an unclassified `AttributeError`.
- SARIF export includes `level` (from scanner severity) and `endLine`, so code-scanning consumers keep the severity instead of treating every result as a warning.
- Source excerpts use the parser's line numbering (LF, plus a lone CR for Python) instead of `str.splitlines()`. U+2028/U+0085 in JavaScript or Python strings no longer shift contextual, builtin, investigation and assistant excerpts to the wrong line, and a Python file with classic-Mac CR line endings no longer fails the whole contextual research run. The index version advances to contextual-3 so affected cached summaries are rebuilt; historical runs keep their recorded version.

## 1.0.0 — scoped offline investigation workbench

- Explicit release scope and acceptance evidence in RELEASE_1_0.md; Directive 002 remains broader.
- Structured/filterable research tabs, paginated rows, expandable evidence, verified historical source excerpts and optional JSON; pt-BR investigation labels and consistent tree styling.
- Configurable logical cache/history/run admission limits, conservative unreferenced-cache preview/cleanup and startup recovery for abandoned jobs. Completed evidence and human review history are preserved.
- 60 frozen external cases from Bandit/WebGoat, baseline plus measured fixes; real Prisma/Taxonomy source observations and 1,501-file repeated-run/cancellation/process-loss QA.
- Python SQL formatting calls and implicit/literal-truthy shell boundaries gain explicit warning coverage with negative controls.
- Source indexing deadline and explicit SQLite backup/restore connection cleanup on Windows.
- Portable release QA from the actual extracted ZIP, fresh restricted environment, manifest checks and previous-package data upgrades. The existing Windows host is verified; a clean OS/VM is not claimed.
- Pre-publication review: cache-maintenance results survive automatic GUI refresh; portable backup and restore validate completed research snapshot references even when the run has no findings.

## 0.5.1 — parser hardening and recognizable brand

- Black minimalist skull with descending sword; vector sidebar/window icon and generated Windows EXE icons.
- One isolated parser worker per research/benchmark job, private bounded JSON, cancellable pipe transport and enforced per-file deadline.
- Windows Job Object committed-memory ceiling (512 MiB default), peak measurement and worker cleanup on parent exit. Failure to attach the Windows quota fails the run.
- Relative JS/TS named/default/namespace imports follow only unique indexed exports, including aliases and anonymous default functions; ambiguous, private, type-only and re-export targets remain gaps.
- Server Action directives after comments are recognized; nested Python function/class/lambda calls are excluded from outer-function observations.
- Recorded analyzer versions preserve historical symbol queries; index version advances to contextual-2. Existing schema 4 and reviews remain compatible.
- Backup restoration retries brief Windows directory-access/sharing contention, remains cancellable and rechecks that the destination is new on every attempt.
- CLI scan progress uses stderr, leaving stdout as one parseable JSON scan record.
- Evidence graph entry points distinguish function/class identity even when routes share a source line.

The parser process is not a filesystem/network/privilege sandbox. Whole-application CPU/RAM/disk
quotas, retention, Java/C# DI resolution and broader independent evaluation remain pending.

## 0.5.0 — contextual research development on testes

Schema 4 evidence graphs and syntax caches; selected Next.js/Spring/ASP.NET profiles; provisional
resource-access/policy-difference hypotheses; bounded direct-call dependencies; separate-axis
review queue; typed local Qwen investigation with cited evidence/fallback; retained security deltas;
two synthetic loopback HTTP labs; a separate measured 12-case benchmark and a real Research page.
Python slices retain conditional alternatives/sanitizer uncertainty. Reports check intermediate
file integrity. No general reachability, confirmed vulnerability or complete Directive 002 claim.

## 0.4.0 — 2026-10-10

- Safe public HTTPS Git import: isolated no-checkout clone, verified raw blobs, bounded staging, refresh and redacted source comparison.
- Persisted per-scanner lifecycle, duration, errors and provenance, including zero-warning/unavailable runs.
- Explicit advisory-alias correlation scoped to project, manifest, ecosystem, package and version; raw scanner/rule history retained.
- Ten Semgrep rules with positive/corrected JavaScript, TypeScript, Java and C# controls.
- Bounded Python assignment slices, conservative import shadowing, syntactic caller references and source-integrity report checks.
- Live Qwen 3.5 4B verification, UTF-8 JSON budgets, incomplete-output/advisory/URL guards, cancellable HTTP and Windows cross-process generation coordination.
- Read-only Windows RAM and optional NVIDIA telemetry; installed Ollama discovery.
- Known schema 1–3 recovery/migration, preserving previous-snapshot comparison references and scanner history.
- Portable native Windows GUI + CLI executables with shared dynamic runtime, complete Qt sources/notices and SHA-256 manifest.
- Portuguese quick-start guide and expanded engine/security/native GUI regressions.

## 0.3.0 — 2026-10-10 (testes branch)

- Portable research ZIP backups include SQLite and every retained current/historical source snapshot.
- Restore verifies bounded file inventory, SHA-256, canonical SQLite schema and foreign keys before publication.
- Relocated project/evidence paths preserve investigations, reviews, reports and laboratory history.
- Recovery pauses schedules, clears stale diagnostics and requires explicit source relinking before refresh.
- GUI background backup/restore and data-directory switching; CLI `--complete` and `relink` commands.
- Cooperative OS data-directory lock prevents competing scans/imports from changing backup snapshots.
- Cancellation, corruption, unsafe archives, destination races, portability and native UI recovery regressions.

## 0.2.0 — 2026-10-10 (testes branch)

- Explicit local Windows x64 scanner installation from pinned official releases and SHA-256 checks.
- Public OSV PyPI/npm feed and Trivy vulnerability DB refresh, separate from offline project scans.
- Managed executable tamper detection, isolated scanner environment and cache diagnostics in the GUI.
- Trivy configuration scans work without a vulnerability DB; updates, telemetry and external modules are disabled.
- OSV 2.6 cache compatibility, fixed-version evidence, Trivy source lines and scanner/feed provenance.
- Opt-in live scanner tests with vulnerable and corrected local fixtures.
- Public GitHub repository with main/testes and verified Windows CI tests plus isolated wheel builds.

## 0.1.0 — 2026-10-10

- First working native Windows GUI and shared-engine CLI.
- Local snapshot ingestion with ZIP/file boundaries and SHA-256 provenance.
- SQLite WAL persistence, transactional versioned migrations and database backup/recovery.
- Six bundled Python/secret/configuration detections and trusted Semgrep rules.
- External scanner adapters with normalized output and explicit missing/error states.
- Historical observations, conservative equivalent-rule correlation and review lifecycle.
- Source investigation, checksum-matched SQL laboratory and corrected regression.
- Local schema-constrained Ollama drafts with deterministic fallback and editable exports.
- Opt-in in-app offline schedules, real metrics, manual rewards/time, diagnostics and rotating logs.
- Original monochrome sword/skull SVG, dark theme, navigation localization and native worker smoke tests.
