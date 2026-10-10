# Scanner coverage and setup

| Engine | Scope and current verification | Requirements |
|---|---|---|
| Builtin | Python AST eval/exec, shell, pickle/yaml, weak hash, formatted SQL; literal credential and debug/privilege patterns. Real execution tested. | Bundled |
| Semgrep CE | Four bundled patterns: Python/JS/TS eval, Java Runtime.exec, C# Process.Start. Real Windows fixture execution tested. | Semgrep 1.180.0 on PATH |
| Gitleaks | `dir`, trusted default-rule config, complete redaction, JSON normalization. Parser/failure tests only. | Installed binary |
| OSV v2 | Recursive `scan source --offline`, trusted config, package/advisory normalization. Parser/failure tests only. | Installed v2 binary and offline databases |
| Trivy | `fs`, cached vulnerability and configuration checks, trusted config. Parser/failure tests only. | Installed binary and cached DB |

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

Use only verified official releases for optional binary installation. Download/verify them manually,
place executables outside imported projects and add to PATH, then rerun diagnostics:

- [Semgrep CE](https://semgrep.dev/products/community-edition)
- [Gitleaks releases](https://github.com/gitleaks/gitleaks/releases)
- [OSV installation](https://google.github.io/osv-scanner/installation/)
- [Trivy installation](https://trivy.dev/docs/latest/getting-started/installation/)

The adapter argument contracts follow official [Semgrep CLI](https://docs.semgrep.dev/cli-reference),
[Gitleaks README](https://github.com/gitleaks/gitleaks) and [OSV usage](https://google.github.io/osv-scanner/usage/).
Gitleaks currently states feature development has ended while security fixes continue; reevaluate
its successor before expanding this integration. Neither ZAP, Nuclei nor CodeQL is integrated.
