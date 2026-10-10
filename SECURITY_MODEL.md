# Security model

Offline Research is the only project execution mode available in 0.3.0. There is no external active scanner,
credential validation, destructive test, report submission or arbitrary target execution feature.
The policy validator rejects ambiguous scope, excludes hosts, requires exact lowercase hosts,
reviewed revision, category/automation permission and explicit approval. It is preparatory logic,
not sufficient production enforcement for an active executor. DNS resolution/rebinding, redirects,
port boundaries and outbound firewall enforcement must be implemented before active testing.

Imported repositories are untrusted data. Files are copied with explicit indexing, size/count/total
byte limits, hashes and provenance. Generated directories and Git metadata are excluded. Filesystem
links/junctions are not followed. ZIP entries reject traversal, absolute/Windows drive paths,
symlinks, reserved Windows names, case-colliding duplicate paths and configured oversized output.
No source hooks, build/installation scripts, dynamic imports or downloaded plugins run automatically.

External scanners use registered executable names, fixed typed argument assembly, shell=False,
trusted configuration outside the snapshot, reduced credential/interpreter environment, timeouts,
output limits and process-tree cancellation. Executables inside scanner working directories are
rejected. Managed Windows installations verify pinned official release SHA-256 values and check
binary receipts before selection. Other tool discovery trusts the operator's PATH; do not put
repository directories in PATH. Receipts are local integrity records, not a defense against an
attacker who can replace both the executable and its receipt. Release signature verification and
complete Windows reparse/TOCTOU hardening remain pending. Native scanners are trusted software,
not sandboxed against malicious inputs.

Scanner installation and advisory refresh are explicit network operations against public feeds;
they receive no source or dependency metadata. Source scans never refresh feeds. OSV disables
network features, resolution and call analysis. Trivy disables DB/Java/check/version updates and
telemetry, uses an empty controlled module directory and an explicit ignore/config file, and
disables dependency API requests. These CLI controls do not constitute an OS network sandbox.
OSV feed hashes are checked before scans; Trivy presence/metadata is recorded, with native scanner
validation on use. The native Trivy downloader's temporary disk use is not OS quota constrained;
the app requires 4 GB free disk and validates the completed DB size/schema.

Sensitive assignment patterns, common GitHub/AWS/JWT tokens and private-key blocks are redacted
before normalized finding serialization and UI/log/report exposure. Gitleaks Match and Secret fields
are discarded. These rules cannot identify every possible proprietary credential format. Managed
snapshots retain raw source on disk, so protect the local data directory using normal Windows access
controls; at-rest encryption and secure token storage are not implemented.

Ollama uses local HTTP without redirects/proxies. Generated text never changes policy, executes
commands, marks evidence verified or submits reports. Schema validation constrains structure, not
truth. Human verification and false-positive decisions require notes. Local reproduction requires
a passing validation record and is restricted to a checksum-matched bundled lab fixture.

SQLite SQL values are parameterized. Reports escape HTML, and Markdown is edited/displayed as plain
text. Complete research backups validate bounded ZIP paths, entry types, SHA-256/size inventory,
foreign keys and the exact known SQLite schema; custom executable triggers/views/indexes are rejected.
Restore relocates snapshots into a new data home, pauses schedules and requires explicit source
relinking before refresh. Backups contain raw source and are not encrypted or signed. Legacy
database-only backups do not relocate evidence. Existing destinations are not overwritten. All UI
research tasks have auditable persisted results; rotating logs avoid unlimited growth. Scheduler
jobs are offline and opt-in. Shutdown cancels workers and external process trees.

Limits do not enforce OS-level CPU/RAM quotas. Plugins execute as the current Windows user and must
be trusted. Source snapshots and old history are retained until an operator manages retention.
