# Architecture

The GUI and CLI invoke `Engine`, `Ingestion`, `Database`, and reporting services directly.
Domain modules have no Qt imports. Python 3.12+, Pydantic v2 and PySide6 Essentials provide the
runtime. Essentials contains the actual Widgets and SVG modules used; Addons is unnecessary.

SQLite uses WAL, foreign keys, short per-operation connections and transactional numbered
migrations (`PRAGMA user_version`). This deliberately uses the standard-library sqlite3 layer
instead of SQLAlchemy: the current small schema needs no ORM, and explicit parameterized SQL
keeps migration and backup semantics observable. Migration failure rolls back atomically.

Tables store programs/policies, projects/manifests, scans, normalized findings, immutable
scanner observations, reviews/notes, reports, validation evidence, settings, audit records,
schedules and manually entered research returns. Version 2 retains separate scanner observations
when equivalent alerts are correlated.

Imports create snapshots under `projects/`. SHA-256 indexes establish provenance. Refresh creates
a new snapshot and swaps project metadata transactionally. Previous snapshots remain available
for finding evidence. There is no automatic cache deletion or Git hook execution.

Scans acquire an OS file lock per project, record their lifecycle, index the snapshot and submit
scanner jobs to a bounded thread pool. The GUI owns a QThread for each user task and uses signals
to update widgets. External tool subprocesses receive fixed arguments, sanitized environments,
temporary working directories, deadlines, output limits and cancellation signals. Windows
process-tree termination uses the system taskkill binary. A GUI permits one foreground research
job at a time; scanner jobs within it can run concurrently. Cross-project fair queues are pending.

Fingerprints use project, explicit rule family, path and line. Only bundled Python dynamic-code
and Semgrep eval rules have an established cross-engine equivalence. Arbitrary same-CWE findings
are not merged. Same-file findings remain related investigation references. Line shifts can create
new occurrences; semantic fingerprints and multi-language dataflow are roadmap items.

The desktop schedules persisted offline profiles only while open, enabled and idle. Schedule
claims are transactional. Closing requests cancellation and waits asynchronously for workers;
it installs no startup worker.

Ollama has a loopback-only HTTP client, no redirects/proxies, a process-local generation lock,
schema-constrained drafts, bounded prompts, timeout/cancellation watchdog and `keep_alive=0`.
AI prose is provisional. Deterministic report fields are read directly from stored evidence.

Trusted plugins register explicitly through `Registry`; no internet downloads, automatic entry
points or arbitrary AI-generated commands are executed. Python plugins are not a sandbox.
