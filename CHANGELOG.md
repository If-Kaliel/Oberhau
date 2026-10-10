# Changelog

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
