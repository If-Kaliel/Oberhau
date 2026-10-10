# Architecture

0.5.0 adds the domain-only [research subsystem](RESEARCH.md): `framework_analysis` indexes
Tree-sitter/Python syntax, `research_models` validates bounded evidence and `research` constructs
graphs/hypotheses, reuses per-file cache and ranks the queue. `git_intelligence` compares retained
observations; `research_assistant` exposes typed read tools to existing Ollama. `local_validation`
owns disposable synthetic HTTP recipes and `benchmark` evaluates a separate dataset. Schema 4
stores runs/caches/assistance and reuses findings/reviews/scans. Graph/finding publication is atomic.
The new `desktop/research_page.py` renders real records without moving existing page behavior.

The GUI and CLI invoke `Engine`, `Ingestion`, `Database`, and reporting services directly.
Domain modules have no Qt imports. Python 3.12+, Pydantic v2 and PySide6 Essentials provide the
runtime. Essentials contains the actual Widgets and SVG modules used; Addons is unnecessary.

SQLite uses WAL, foreign keys, short per-operation connections and transactional numbered
migrations (`PRAGMA user_version`). This deliberately uses the standard-library sqlite3 layer
instead of SQLAlchemy: the current small schema needs no ORM, and explicit parameterized SQL
keeps migration and backup semantics observable. Migration failure rolls back atomically.

Tables store programs/policies, projects/manifests, scans, normalized findings, immutable
scanner observations, reviews/notes, reports, validation evidence, settings, audit records,
schedules and manually entered research returns. Schema 3 adds per-scanner lifecycle/provenance rows, an explicit scoped advisory index and observations distinct by scanner/rule/scan.

Imports create snapshots under `projects/`. SHA-256 indexes establish provenance. Refresh creates
a new snapshot and swaps project metadata transactionally. Previous snapshots remain available
for finding evidence. There is no automatic cache deletion or Git hook execution.

Scans acquire an OS file lock for the data directory and per project, record their lifecycle, index the snapshot and submit
scanner jobs to a bounded thread pool. The GUI owns a QThread for each user task and uses signals
to update widgets. External tool subprocesses receive fixed arguments, sanitized environments,
temporary working directories, deadlines, output limits and cancellation signals. Windows
process-tree termination uses the system taskkill binary. A GUI permits one foreground research
job at a time; scanner jobs within it can run concurrently. Imports, refreshes, relinks and complete
backups share the data-directory lock across threads/processes. Cross-project fair queues are pending.

`backup.py` captures SQLite through its online backup API and streams every retained source snapshot
into a versioned ZIP with per-file SHA-256/size metadata and directory inventory. Project roots and
finding/observation snapshot references become relative in the bundle. Restore validates bounded
archive contents and the exact canonical schema before rewriting references to a new data home,
disabling schedules and requiring explicit source relinking. It publishes the staged directory only
after verification. Database remapping uses bounded batches; optional binaries/caches are excluded.

Fingerprints use project, explicit rule family, path and line. Only bundled Python dynamic-code
and Semgrep eval rules have an established cross-engine equivalence. Arbitrary same-CWE findings
are not merged. Same-file findings remain related investigation references. Line shifts can create
new occurrences; semantic fingerprints remain a roadmap item. Dependency correlation uses explicit advisory aliases within a package/ecosystem/version/manifest scope. The ten-rule Semgrep pack includes bounded multi-language request flows; Python investigation adds a conservative same-function assignment slice.

The desktop schedules persisted offline profiles only while open, enabled and idle. Schedule
claims are transactional. Closing requests cancellation and waits asynchronously for workers;
it installs no startup worker.

Ollama has a loopback-only HTTP client, no redirects/proxies, a local generation lock plus Windows named-mutex process coordination,
schema-constrained drafts, bounded prompts, timeout/cancellation watchdog and `keep_alive=0`.
AI prose is provisional. Deterministic report fields are read directly from stored evidence.

Trusted plugins register explicitly through `Registry`; no internet downloads, automatic entry
points or arbitrary AI-generated commands are executed. Python plugins are not a sandbox.

`repositories.py` performs isolated shallow Git acquisition and exports checksum-verified raw blobs. Refresh retains previous commits/manifests/snapshots for bounded redacted diffs. `resources.py` provides optional RAM/NVIDIA telemetry. `packaging/Oberhau.spec` builds two EXE entry points sharing one dynamic Python/Qt runtime; the build script includes complete library sources and notices.
