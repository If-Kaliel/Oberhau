# Oberhau 1.0 — release scope and evidence

The 1.0 scope is an **offline investigation workbench for authorized source review** on Windows
11 x64. It imports verified snapshots, runs bounded static checks, presents evidence and provisional
questions, records human review and exports drafts. Optional scanners and local Qwen require explicit
setup. It does not promise automatic vulnerability confirmation or completion of Directive 002.

## Four acceptance areas

1. **External evaluation:** 60 fixed labelled cases from upstream Bandit and WebGoat, original
   bytes pinned by commit and SHA-256. Labels were frozen before the first execution. The initial
   result was 23 TP / 0 FP / 20 TN / 17 FN. Five corrections to SQL-formatting/shell syntax raised
   this to 28 TP / 0 FP / 20 TN / 12 FN. The same dataset subsequently informed those corrections;
   the final score is not a blind holdout score. All misses remain in the report. Nine concern SQL
   construction without an execution call; three concern custom authorization lessons. No general
   authorization detection claim follows from the small synthetic benchmark.
2. **Investigation experience:** readable hypothesis/evidence/queue/assistant/benchmark rows,
   filtering across results, 200-row pagination, expandable evidence, plain-text detail and optional
   technical JSON. Source navigation verifies the historical snapshot SHA-256 and redacts recognized
   secrets. Core controls and investigation labels support pt-BR; technical identifiers and some
   backend descriptions retain English. Qt regressions exercise filtering, pagination, source
   navigation, tamper rejection, workers, backups and labs. Native screenshots are visually checked.
3. **Long operations and retention:** 1,501-file synthetic repository, ten consecutive completed
   runs, incremental reuse, cancellation with no partial contextual findings, actual owned-process
   termination and subsequent startup recovery/cache reuse. Default logical limits are 64 MB syntax
   cache, 256 MB research history/assistance and 500 research runs per project. At capacity, new
   research writes stop; limits are configurable. Cleanup previews/removes only cache records unused
   by completed historical runs. Human decisions, reports, observations, source snapshots and run
   evidence are preserved. This is admission control, not an OS disk quota or automatic evidence
   deletion. Complete backup and a new data directory support archival without silently deleting work.
4. **Distribution and compatibility:** portable GUI/CLI with shared Python/Qt, per-file manifest,
   archive checksum and Qt sources/licenses. QA extracts the actual release into a new directory,
   uses fresh application/user/temp data and a system-only PATH, tests both EXEs, research/parser
   limits, assistant fallback, labs, maintenance, backup/restore and upgrades from the actual 0.4.0
   and 0.5.1 packages. The current host is Windows 11; a freshly installed OS/clean VM is not available
   here and is **not claimed as tested**. Executables remain unsigned; an installer is not required
   for this portable scope. Publication and merging into main are separate release actions.

## Real application observations

A complete Taxonomy snapshot at `298a8857c7128a0d121e7f699dfd729f23b3966d` has 188 files;
129 syntax files produced 121 symbols, eight endpoints and four provisional review signals.
Manual review found counterevidence in the access-check helper, session identity guard and signed
webhook processing. These are documented as possible unnecessary review signals, not discovered
vulnerabilities. Domain policy, identity trust, signature semantics and branch dominance remain
unresolved. The Prisma Next.js example subset indexed successfully, but has no supported exported
route/Server Action entry points; its absence of hypotheses is not a security verdict.

Neither application has independent vulnerability labels; neither contributes to the confusion
matrix. Imported applications, package scripts and dependencies were never executed.

## Reproduce the release checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.oberhau\release-tests
.\.venv\Scripts\python.exe scripts\prepare_external_evaluation.py
.\.venv\Scripts\python.exe scripts\evaluate_external.py
.\.venv\Scripts\python.exe scripts\stress_release.py
.\.venv\Scripts\python.exe scripts\build_windows.py
.\.venv\Scripts\python.exe scripts\verify_windows.py
```

Only the explicit preparation/build steps download public sources. The evaluation verifies their
recorded hashes; it never executes those sources. Existing fixed labels must not be regenerated to
fit observed predictions. The scripts, source/label manifests and baseline are versioned under
`scripts/` and `evaluation/`; detailed current results are recorded in WORKLOG.md and release artifacts.

Sources: [Bandit examples](https://github.com/PyCQA/bandit/tree/68ebe11ef79263be27ec223184b94a4fc394a622/examples)
(Apache-2.0), [WebGoat lessons](https://github.com/WebGoat/WebGoat/tree/044948d057b249735be2bfc14eccc9e3dc2eac34/src/main/java/org/owasp/webgoat/lessons)
(GPL-2.0-or-later), [Prisma examples](https://github.com/prisma/prisma-examples/tree/caa902a819be2e8fe1e0b0ec2f543e9220cf69cc/orm/nextjs)
(Apache-2.0), [Taxonomy](https://github.com/shadcn-ui/taxonomy/tree/298a8857c7128a0d121e7f699dfd729f23b3966d)
(MIT). Downloaded external source files/licenses remain evaluation inputs and are not bundled in
the application distribution.

## Beyond 1.0

General type/DI/branch/identity analysis, global-policy applicability, Docker/app replay, private Git,
continuous monitoring/unattended pipelines, OS-wide quotas, signed installers and external active
executors remain future scope. [RESEARCH.md](RESEARCH.md) gives the exact supported syntactic subset.
Static warnings and model output always require human review.
