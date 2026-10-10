# Contextual research / Directive 002

Development 0.5.0 adds a functional bounded research workflow to the 0.4.0 workbench. The entire
directive is not complete. Imported source remains data: parsing never loads its dependencies,
starts applications, builds a project or executes its functions. Main retains the stable release.

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
that path. Cancellation is checked before/after each parse and throughout tree/call traversal.

| Profile | Implemented syntax coverage |
|---|---|
| Next.js / JS / TS | Exported App Router `route` handlers; exported functions in files beginning with `use server`; parameters/request-shaped access, assignments, direct calls, identity/validator/resource-filter candidates; middleware/proxy presence as unresolved counterevidence |
| Spring / Java | Mapping annotations; class/method PreAuthorize/Secured/RolesAllowed; selected repository/JDBC operations, selected object-bound permission expressions and security-configuration call candidates |
| ASP.NET / C# | Http method attributes; class/method Authorize and AllowAnonymous override; Map HTTP lambda handlers/chained RequireAuthorization; selected EF/file/process/HTTP calls and owner-filter candidates |
| Python | Indexes top-level functions/sensitive calls; existing finding slices retain conditional assignment alternatives, sanitizer candidates and condition locations |

Calls follow unique direct same-file JS functions and relative named JS imports/aliases, default
depth four and 64 visits per endpoint. Parameter-position identifier dependencies propagate through
those supported calls; constant arguments do not become request input because a helper parameter
is named `id`. Assignments use a conservative dependency union: branch feasibility, reassignment
kills, exception paths and runtime bindings are not solved. Java/C# service dispatch/DI,
default/namespace imports and external dependencies remain unresolved and produce graph gaps.
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
RAM/CPU quotas. Cache retention, native parser process isolation, fair queues, resumable checkpoints,
OS quotas and optional GPU auto-pause remain pending.

The separate benchmark has 12 original MIT synthetic code cases: six expected signals and six
negative controls, distinct from development regression strings. It was first executed after initial
analyzer tests; no blinded or external independent curation is claimed. Dataset SHA-256 identifies
evaluations. Reports retain expected/detected/missed signals, false positives, precision, recall,
time, Python allocation peak and Windows process memory with scope caveats. This small dataset is
not representative; no zero-day/production detection claim follows. An external licensed corpus is pending.

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
| 15 | Real measurements on small separate synthetic dataset; externally curated realistic benchmark pending |

Broader dataflow/business-logic proof, frontend/backend boundaries, service dispatch, full policy
applicability, unattended multi-stage refresh/AI/lab automation, notifications, expanded lab classes,
stronger semantic AI claim checks and independent real-world evaluation need further development.
