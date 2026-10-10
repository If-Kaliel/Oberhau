# Troubleshooting

**Python command fails or opens Microsoft Store:** the initial machine's `python` alias and `py`
registration pointed to missing executables. Use the prepared `.venv\Scripts\python.exe` here.
On a new installation, install a complete Python and pass its explicit path to Setup.ps1.

**GUI does not launch:** run `scripts\Run-CLI.ps1 gui` in PowerShell to see the error. Check installed
PySide6 Essentials and Pydantic. pythonw intentionally opens without a terminal window.

**Scanner missing:** rerun System diagnostics after installing its official verified executable
outside imported source and adding it to PATH. The launcher prepends this project's .venv Scripts.

**Semgrep socketpair EACCES:** the Codex execution sandbox blocks Semgrep's internal sockets. The
integration worked outside that sandbox on the local lab. Launch normally in Windows; do not change
the target's authorization or enable external testing to address this host restriction.

**Dependencies profile fails:** no matching scanner is installed or no offline database exists.
Install/cache OSV or Trivy according to their official instructions. Quick Scan remains available.

**Qwen unavailable:** start your local Ollama application and rerun diagnostics. Select an installed
model. Reports fall back to deterministic templates. Missing Ollama does not prevent application launch.

**Archive/import rejected:** inspect the error for paths, links or configured size limits. Untrusted
archives containing traversal/duplicate/reserved paths are intentionally rejected. Inaccessible Git
commit metadata may block a Git source import; plain folder/file imports remain available.

**Worker busy:** wait or use Stop / Escape. The GUI supports one research task at a time. Scanner
subtasks can run in parallel. Closing requests cancellation and waits without freezing the interface.

**Crash during scanning:** on the next scan of that project, the OS lock is acquired and previous
running records are marked interrupted. Complete scanner observations already committed are retained.

**A finding disappeared:** absent warnings are not proof of remediation. Review the stored excerpt,
refresh snapshots and document a corrected regression before manually marking Fixed.

**Backup missing source:** database backups contain metadata and reports, not repository files.
Copy the entire data directory when preserving evidentiary snapshots. See USER_GUIDE.md for recovery.
