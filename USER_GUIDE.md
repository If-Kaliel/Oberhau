# User guide

1. Launch `Launch-Oberhau.cmd`. Complete first-run resource setup; optionally import the labeled lab.
2. Add a program under Programs if applicable. Record the official policy URL and exact scope
   hosts in the JSON editor. Double-click a program to update it. Material policy changes increment
   revision and invalidate its reviewed flag. This release does not conduct active tests.
3. Under Projects, import an authorized local folder, individual file or ZIP. Choose a program or
   independent offline research. Oberhau analyzes its managed copy, never installs or runs its code.
4. Choose the project and actual profile under Scanner. Quick uses bundled checks; Standard adds
   installed Semgrep. Missing requested engines make coverage partial, or failed if none can run.
5. Use Investigations search, double-click a finding, inspect its redacted excerpt and checksum
   status, review previous observations, then save a lifecycle decision with supporting notes.
6. Laboratory validates only the unchanged bundled SQL finding. It records observed behavior and
   proves the parameterized control rejects the same input. Other findings require human validation.
7. Reports generates deterministic or local Qwen drafts. Review and edit the text, then export
   `.md`, `.html`, `.json` or `.sarif`. Double-click a historical report to reopen it. Exporting an
   edited draft creates a new history record. Reports are never submitted automatically.
8. Refresh a local folder or source file's snapshot explicitly after changing source. Changed scans compare file
   hashes against the last completed manifest. Removed warnings are not automatically marked fixed.
9. Add an offline schedule after choosing project/profile on Scanner. Enable schedules explicitly
   on Automation. Jobs analyze the stored snapshot while the GUI is open and idle.
10. Analytics records actual paid rewards and hours manually; it never uses advertised maxima.

Shortcuts: Ctrl+O imports a folder; Ctrl+R reloads persisted tables; Ctrl+F focuses page search;
Escape requests cancellation. Table headers resize/sort and investigation context menus open evidence.

Settings persists language (applies on restart), scanner concurrency, deadlines and loopback Ollama
preferences. System diagnostics runs asynchronously and reports executable paths, versions, model
availability and installation guidance. Diagnostic exports contain local filesystem paths.

Back up the SQLite database using Settings or CLI. Also copy the entire data directory's projects
and logs for complete evidence recovery; a database-only backup cannot reconstruct source snapshots.

```powershell
.\scripts\Run-CLI.ps1 backup 'C:\Backups\oberhau-2026-10-10.sqlite3'
.\scripts\Run-CLI.ps1 restore 'C:\Backups\oberhau-2026-10-10.sqlite3' 'C:\Recovery\oberhau.sqlite3'
```

Restore refuses to overwrite an existing file. Close Oberhau and point `OBERHAU_HOME` at the
recovered data directory containing `oberhau.sqlite3` and the original project snapshots. Snapshot
paths are currently absolute; moving a backup to a different computer requires reimporting source.
