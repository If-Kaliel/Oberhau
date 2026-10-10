# Scanner coverage and setup

| Engine | Scope and current verification | Requirements |
|---|---|---|
| Builtin | Python AST eval/exec, shell, pickle/yaml, weak hash, formatted SQL; literal credential and debug/privilege patterns. Real execution tested. | Bundled |
| Semgrep CE | Four bundled patterns: Python/JS/TS eval, Java Runtime.exec, C# Process.Start. Real Windows fixture execution tested. | Semgrep 1.180.0 on PATH |
| Gitleaks | `dir`, trusted default-rule config, complete redaction; real fabricated GitHub credential and corrected control verified. | Managed 8.30.1 or trusted PATH binary |
| OSV v2 | Recursive `scan source --offline`, no resolution/call analysis, trusted config; real Django advisory matching and fixed-version evidence verified. | Managed 2.6.0 and downloaded ecosystem feed |
| Trivy | `fs`, configuration and vulnerability checks selected by profile; real Dockerfile line attribution and Django advisory/control verified. | Managed 0.75.0; vulnerability DB needed only for dependency/Deep scans |

No adapter installation is misrepresented as working scanner availability. Diagnostics executes a
version command, records failures and lists missing components. Availability does not prove that
databases are prepared or a scan will succeed. Network metadata indicates a tool's general database
needs; execution arguments request cached/offline modes.

Profiles expose their exact description in Scanner and `engine.PROFILES`. Quick works with no
external binary. Standard adds Semgrep; Deep requests all available offline engines; Changed scans
bundled checks only; Secrets requests bundled credential patterns plus Gitleaks; Configuration
requests bundled configuration checks plus Trivy; Dependencies requests OSV and Trivy. Requested
missing/failed engines produce partial or failed scan states and persisted errors.

Warning severity is distinct from detection confidence. Dependency version matching never means
application reachability. Missing authorization, IDOR, SSRF, CSRF, business logic, race conditions,
framework access boundaries, full taint flows and novel exploit discovery are not covered by the
small bundled rules. They require expanded trusted rule packs and manual investigation.

Semgrep uses explicit locally bundled MIT rules, metrics off, version checks off, no cloud upload,
no logged-in token, and no target build. Remote registries and arbitrary repository rule files are
not selected. Rule-manager/custom packs and Git-history secret scans are future work.

Use the Scanner page's explicit download buttons or the equivalent CLI commands:

```powershell
.\scripts\Run-CLI.ps1 install-tool gitleaks
.\scripts\Run-CLI.ps1 install-tool osv-scanner
.\scripts\Run-CLI.ps1 install-tool trivy
.\scripts\Run-CLI.ps1 refresh-osv-cache PyPI
.\scripts\Run-CLI.ps1 refresh-osv-cache npm
.\scripts\Run-CLI.ps1 refresh-trivy-cache
```

These operations require Internet, fetch public releases/feeds, and send no project information.
Binary versions and published release SHA-256 values are pinned in `assets/tools.json`; install
receipts record binary hashes and are checked before managed binaries are selected. Managed files
stay under the chosen `--home` directory. No administrator permission or global PATH mutation is
required. Other trusted binaries on PATH remain supported; pinning applies to managed installation.
Source archives, configuration files and scripts from imported projects never install tools.

OSV 2.6.0 appends `osv-scalibr` to the selected cache root; the old documentation's `osv-scanner`
subdirectory does not work for this version. Oberhau sets the cache environment itself and validates
feed hashes. PyPI's verified feed was about 36 MB; Trivy's expanded database was about 1.47 GB.
Trivy refresh requires 4 GB free disk space. Java index DB refresh is not implemented; Java archive
analysis can fail explicitly without that additional cache. No automatic feed updates occur during
scans. Trivy uses embedded configuration checks with check updates disabled. Its cache presence
indicator does not certify every database ecosystem or its freshness; metadata is in diagnostics.

Findings preserve managed version, executable checksum, Semgrep rule checksum, and relevant
advisory-feed receipt. Fixed versions are advisory evidence across potentially multiple release
branches, not a tested upgrade plan. Alias-overlapping advisories remain distinct findings.

Optional manually installed executables must be outside imported projects. Official sources:

- [Semgrep CE](https://semgrep.dev/products/community-edition)
- [Gitleaks releases](https://github.com/gitleaks/gitleaks/releases)
- [OSV installation](https://google.github.io/osv-scanner/installation/)
- [Trivy installation](https://trivy.dev/docs/latest/getting-started/installation/)

The adapter argument contracts follow official [Semgrep CLI](https://docs.semgrep.dev/cli-reference),
[Gitleaks README](https://github.com/gitleaks/gitleaks) and [OSV usage](https://google.github.io/osv-scanner/usage/).
Gitleaks currently states feature development has ended while security fixes continue; reevaluate
its successor before expanding this integration. Neither ZAP, Nuclei nor CodeQL is integrated.
