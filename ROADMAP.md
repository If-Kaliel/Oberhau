# Roadmap against the master specification

The first release delivers functional portions of milestones 1–5, 7 and 8. No complete-product
claim is made; larger unsupported capabilities remain explicit.

Next implementation order:

1. Delivered in 0.2.0: live Gitleaks/OSV/Trivy tests, verified Windows installation, explicit public
   advisory downloads, cache metadata, executable/rule/feed hashes and fixed-version evidence.
   Still pending: per-scanner run timing/status records even when zero warnings, Java index refresh,
   advisory-alias correlation, signed release verification and additional ecosystem caches.
2. Delivered in 0.3.0: portable database/current/historical snapshot backup, validated recovery to
   a new data directory, relocated evidence and explicit source relinking. Still pending: hardened
   Windows reparse/TOCTOU handling, trusted configurable executable paths/checksums and OS quotas.
3. Git URL cloning with repository policy/provenance, safe clone/update and commit comparison;
   trusted rule management and expanded JS/TS/Next.js, Spring and ASP.NET profiles.
4. Semantic finding fingerprints, confidence rationale, reachability/AST caller tracing,
   re-review after security-sensitive changes, scan result caching, checkpoints and fair queues.
5. Live Qwen regression on qwen3.5:4b, token-aware chunking, per-evidence citations, retry policy,
   stronger fact/claim checks, process-wide model arbitration and explicit GPU telemetry.
6. Additional trusted local validation recipes, isolated local HTTP fixtures and optional Docker
   labs. Never execute arbitrary imported code as part of ingestion.
7. Full policy editor (eligibility, advertised ranges, prohibited categories, review expiry),
   explicit authorization lifecycle, then guarded local ZAP/Nuclei. External testing requires a
   separately reviewed executor with URL/DNS/redirect/port/category/budget enforcement.
8. Scheduler repository-change checks, advisory refresh opt-in, persisted notifications, retention,
   pause during gaming, safe retries and separate worker lifecycle opt-in.
9. Complete pt-BR translations, accessible labels/tooltips for every control, report completeness
   editor, metric filters/plots, actual ROI/status statistics and detailed engine performance.
10. Plugin process isolation, scanner contract versioning, Windows packaging/installer, signed or
    checksum-verifiable release assets, distribution license compliance and full GUI E2E tests.

Currently unsupported: automatic auth/IDOR/business-logic detection, broad taint analysis, exploit
generation, proof of novelty, automatic bug-bounty submission, CodeQL, ZAP/Nuclei, remote Git imports,
general test execution, Docker, Java scanner cache downloads, installer EXE, OS quotas and cloud integrations.
