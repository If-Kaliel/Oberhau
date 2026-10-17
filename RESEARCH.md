# Contextual research / Directive 002

Version 1.0 continues the bounded research workflow introduced in 0.5.0. The entire
directive is not complete. Imported source remains data: parsing never loads its dependencies,
starts applications, builds a project or executes its functions. Main retains the stable release.

[RELEASE_1_0.md](RELEASE_1_0.md) defines the scoped release and external evaluation results.
The Research tabs now use readable/filterable lists, expandable evidence and 200-row pagination;
the filter searches all rows, not just the current page. Select an evidence row and use **View evidence
source / Ver código da evidência** to read a hash-verified historical excerpt. Technical JSON is opt-in.
Failed, cancelled and interrupted research runs are visible; they contain no completed contextual
verdict. Startup recovery marks abandoned jobs interrupted before another project scan is required.

**Automation Control / Controle de automação** also exposes configurable logical storage limits:
64 MB cache, 256 MB research/assistant JSON and 500 runs/project by default. At capacity, research
admission stops with a recovery instruction. Preview/apply cleanup removes only cache records unused
by completed historical runs. Human decisions, run evidence and source snapshots are preserved.
These limits cover research JSON, not total SQLite/WAL, scanner history, snapshots or an OS disk quota.

Select an authorized project on Scanner, then use **Pesquisa contextual / Research**, or run:

```powershell
.\scripts\Run-CLI.ps1 --home .oberhau\research scan PROJECT --profile research
.\scripts\Run-CLI.ps1 --home .oberhau\research research-queue --project PROJECT
.\scripts\Run-CLI.ps1 --home .oberhau\research research-details RUN
.\scripts\Run-CLI.ps1 --home .oberhau\research research-assist RUN
.\scripts\Run-CLI.ps1 --home .oberhau\research research-assist RUN --ai
.\scripts\Run-CLI.ps1 --home .oberhau\research benchmark
.\scripts\Run-CLI.ps1 --home .oberhau\research local-lab authorization
.\scripts\Run-CLI.ps1 --home .oberhau\research local-lab input-validation
```

Replace PROJECT/RUN with actual numeric IDs. Research runs the builtin scanner, hashes the
snapshot, builds/reuses the syntax index, constructs evidence and opens structured hypotheses.
Other scanner profiles remain available separately. Research never implicitly downloads tools,
feeds, source or models. AI and local lab recipes are explicit actions. Existing offline schedules
accept `research` and run only while the desktop is open, enabled and idle.

## Actual analysis subset

Tree-sitter uses pinned small MIT wheels for TypeScript/TSX, JavaScript/JSX, Java and C#. Python
uses its standard AST. Syntax errors exclude a file and appear in coverage limitations. The
Windows 0.25.2 callback parser crashed during verification; the supported native timeout API avoids
that path. Research and benchmarks now parse in a separate trusted worker process, including Python
AST parsing. The parent enforces cancellation and a per-file wall deadline (10 s default, configurable
1–60 s) while the worker performs syntax traversal. A file the worker cannot complete (node or
function budget, per-file deadline, crash or memory-ceiling kill) becomes an explicit coverage gap:
its path and a fixed reason appear in coverage, run and hypothesis limitations and scanner
provenance, no summary is cached, and a fresh worker parses the following files. Excluded files may
hold controls or call targets, so hypotheses from that run carry the gap; hypotheses that were only
in an excluded file are reported as unobserved, not resolved. Gaps are retried on the next run.
The first gap in a run with no completed file is followed by a built-in control parse in a fresh
worker; if that fails too, the parser environment is broken and the run fails. Cancellation, the
investigation deadline, protocol violations (malformed, oversized or identity-mismatched responses),
quota attachment failure, source-integrity mismatches and storage budgets still fail the run without
partial contextual findings. Benchmarks remain fail-closed on any parser failure. Cached summaries
can be reused without starting a worker. The private protocol accepts source bytes and identity,
never commands or modules, and returns only fixed failure reasons, never exception text.

| Profile | Implemented syntax coverage |
|---|---|
| Next.js / JS / TS | Exported App Router `route` handlers; exported functions under a leading `use server` directive, allowing header comments; parameters/request-shaped access, assignments, direct calls, identity/validator/resource-filter candidates; middleware/proxy presence as unresolved counterevidence |
| Spring / Java | Mapping annotations; class/method PreAuthorize/Secured/RolesAllowed; selected repository/JDBC operations, selected object-bound permission expressions and security-configuration call candidates |
| ASP.NET / C# | Http method attributes; class/method Authorize and AllowAnonymous override; Map HTTP lambda handlers/chained RequireAuthorization; selected EF/file/process/HTTP calls and owner-filter candidates |
| Python | Indexes top-level functions/sensitive calls, excluding bodies of nested functions/classes/lambdas; existing finding slices retain conditional assignment alternatives, sanitizer candidates and condition locations |

Calls follow unique direct same-file JS functions and relative named/default/namespace JS imports,
including export aliases and named/anonymous default functions. Cross-file targets must be indexed
exports; private, ambiguous, type-only and re-export targets remain unresolved. Default
exported wrappers do not imply their internal callbacks are exported call targets. Default
depth four and 64 visits per endpoint. Parameter-position identifier dependencies propagate through
those supported calls; constant arguments do not become request input because a helper parameter
is named `id`. Assignments use a conservative dependency union: branch feasibility, reassignment
kills, exception paths and runtime bindings are not solved. Java/C# service dispatch/DI,
JS re-exports/package resolution and external dependencies remain unresolved and produce graph gaps.
This is not general interprocedural taint analysis.

Two rules open questions: identifier-bearing resource access without observed object controls;
and syntactically related operations whose endpoints have different visible access policies.
Equivalence uses framework and exact call name, not proven business intent. Authentication is
not object authorization. Selected object-filter and Spring permission candidates prevent the
narrow missing-control signal; runtime validity remains unknown. A validator merely referencing
`#id` is not an object permission check. Middleware/global filter candidates are possible
counterevidence, not proven applicable protections. Public-access intent requires human review.

Each hypothesis includes operation, inputs, known execution path, controls, absent visible checks,
limitations, confirmation questions and path/line/SHA-256 evidence. Graph relations distinguish
syntactic dependencies, unresolved bindings and same-file scanner references; none establish
reachability, exploitation or attacker control. Same-file references never merge unrelated CWEs.
Code Flow Viewer displays textual paths/relations; `research-details` exports the graph as JSON.
Existing reports include hypotheses and recheck every referenced file, including intermediate code.

## Persistence, triage and changes

Schema 4 stores runs tied to scans/commits, redacted per-file caches keyed by project/path/hash/
analyzer version and provisional AI histories. Findings, observations, reviews, reports and audits
reuse existing tables. Completed graph and findings publish transactionally. Failed/cancelled runs
have explicit lifecycle; harmless cache work remains reusable. Stale running jobs become interrupted
on the next scan. Portable backups preserve schema/history; older supported schemas upgrade.

Only changed files are parsed again; all cached summaries participate in rebuilding caller/peer
context. The queue exposes separate severity, confidence, evidence quality, local reproduction,
controls, advisories, history, human notes, duplication status and unknown eligibility. Ranking
has reasons. Human false-positive/fixed decisions lower priority but never disappear. This is
local deterministic ranking, not model training or a reward/impact/eligibility prediction.

Git Intelligence compares retained research snapshots: modified sensitive/dependency files, added/
removed control observations, old/new/absent warnings and possible regressions when a signal returns
within the retained 20-run history. Changed intermediate evidence counts even if the endpoint is
unchanged. An absent warning is not automatically fixed; a new local warning is not novel.
Remote monitoring, automatic source refresh and dependency/advisory inference remain separate
or pending. Existing explicit ingestion/Git and offline dependency scanners are preserved.

## Qwen and trusted local validation

AI Research Assistant has seven typed read-only actions: locate function, symbols, references,
calls, excerpt, scanner results and Git changes. Reads use recorded evidence IDs, not paths or
commands; excerpts require confinement and matching snapshot hashes. Limits: three iterations,
two queries per iteration, 6 KB per tool output and 12 KB cumulative context. It reuses loopback-only
Ollama, process arbitration, cancellation and `keep_alive=0`; default remains qwen3.5:4b.
Consulted evidence IDs are mandatory for claims. Unseen citations, unsupported types/CVEs/URLs,
incomplete or malformed output and unavailable Ollama cause deterministic fallback. Structure and
citations do not prove prose truth. Query histories persist; AI never executes code or changes status.

The SQL lab remains. Two trusted HTTP recipes demonstrate resource authorization and numeric input
validation with vulnerable/fixed handlers, synthetic records and observed status/body results.
They bind an ephemeral 127.0.0.1 listener, connect to that exact listener and close sockets/threads.
No target URL, source path or model command is accepted. Validation records have no finding ID:
passing a bundled recipe cannot confirm an imported finding. Docker is unnecessary.

## Resources, benchmark and acceptance

One foreground desktop job and existing scanner/Qwen coordination remain. Research limits are
configurable in Automation Control: defaults 5,000 symbols, 20,000 nodes, four edges per node budget,
32 MB serialized index, depth four and 64 visits. These are structural/cooperative limits, not OS
RAM/CPU quotas for the entire application. On Windows, parser workers join a private Job Object
before source is sent: a configurable committed-memory ceiling (512 MiB default, 128–2048 MiB)
and kill-on-job-close cleanup apply to the worker. Attachment failure fails the run. This is not
a filesystem/network/token sandbox; startup before job attachment and parent graph/SQLite work
remain outside that memory ceiling. Other platforms retain worker/deadline isolation without this
Windows quota. Research JSON admission limits and conservative orphan-cache cleanup are available;
whole-store retention, fair queues, resumable checkpoints, global CPU/RAM/disk quotas
and optional GPU auto-pause remain pending.

The separate benchmark has 12 original MIT synthetic code cases: six expected signals and six
negative controls, distinct from development regression strings. It was first executed after initial
analyzer tests; no blinded or external independent curation is claimed. Dataset SHA-256 identifies
evaluations. Reports retain expected/detected/missed signals, false positives, precision, recall,
time, parent Python allocation/Windows working set and parser Job Object peak committed memory,
with distinct scope caveats. This small dataset is
not representative; no zero-day/production detection claim follows. The additional 1.0 evaluation
uses 60 fixed Bandit/WebGoat cases and records all misses, plus unlabelled real application
observations. [RELEASE_1_0.md](RELEASE_1_0.md) distinguishes baseline, subsequent fixes and scope.
A broader blind/representative real-world evaluation remains future work.

| Directive criteria | Demonstrated subset / limitations |
|---|---|
| 1 | Existing real local/Git import preserved; real source self-research smoke logged separately |
| 2–3 | Selected framework security syntax and sensitive operations; global/type/DI coverage incomplete |
| 4–6 | Positive/negative hypotheses, evidence recovery and control counterexamples; runtime binding unknown |
| 7 | Distinct scanner observations linked by file in graph; semantic equivalence not proven |
| 8 | Working queue with separate axes and human corrections; heuristic adaptation remains partial |
| 9 | Typed/cited Qwen workflow and fallback; actual model verification recorded in WORKLOG |
| 10–12 | SQL and synthetic HTTP regressions, fixed static controls; imported applications never executed |
| 13 | File cache plus full contextual rebuild and retained security deltas; remote monitoring pending |
| 14 | Existing Markdown/HTML/JSON/SARIF exports include hypotheses and cross-file integrity |
| 15 | Original synthetic benchmark plus 60 upstream-source-labelled cases and real application observations; broader blind/representative evaluation pending |

Broader dataflow/business-logic proof, frontend/backend boundaries, service dispatch, full policy
applicability, unattended multi-stage refresh/AI/lab automation, notifications, expanded lab classes,
stronger semantic AI claim checks and independent real-world evaluation need further development.
