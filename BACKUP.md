# Research backup and recovery

Schema 4 preserves contextual graphs, syntax caches, provisional AI histories and synthetic HTTP
validation records. Run snapshots use portable relative references; finding paths are remapped
as before. Restored stale research jobs become interrupted and schedules remain paused.

Oberhau 0.4.0 provides a portable `.oberhau.zip` research bundle. Settings runs backup and restore
in a cancellable background worker. The CLI uses the same service; Ctrl+C requests cancellation.

```powershell
.\scripts\Run-CLI.ps1 --home 'C:\Research\Oberhau' backup 'C:\Backups\research.oberhau.zip' --complete
.\scripts\Run-CLI.ps1 restore 'C:\Backups\research.oberhau.zip' 'C:\Recovery\Oberhau' --complete
.\scripts\Run-CLI.ps1 --home 'C:\Recovery\Oberhau' gui
```

The backup destination must be a new file outside the managed snapshots. Restore creates a new
data directory and refuses an existing destination. In Settings, choose **Restore research**, the
archive, its parent folder, and a new folder name. **Open data directory** opens the recovered
database. To use it on future launches, set `OBERHAU_HOME` or pass `--home`.

## Contents

The bundle includes the SQLite database and all retained directories under `projects/`. This
covers current and previous source snapshots, empty snapshot directories, project IDs/policies,
scans, findings and raw scanner observations, review decisions/notes, reports, laboratory records,
manual rewards/time, settings, schedules and the database audit trail. It rewrites managed project
and evidence paths on recovery, so investigations work in a different Windows folder or computer.
Original source paths remain historical provenance, but their links require explicit review.

Scanner executables and installation receipts, advisory databases/caches, rotating log files,
lock files, exported report files outside snapshots and Ollama model weights are excluded. Install
scanners and refresh public caches separately on the recovery machine. Existing reports and bundled
Quick scans work without those optional tools. Logs are separate operational files; copy them
separately if needed for troubleshooting.

Raw source bytes are preserved, including secrets present in imported source. **The bundle is
not encrypted.** Protect it with suitable filesystem access controls. Report redaction does not
remove secrets from source snapshots. SHA-256 detects file corruption against the manifest; it is
not an authenticity signature. Only restore archives from a trusted origin.

## After recovery

Schedules are disabled, stale running scans become interrupted, and old diagnostics are removed.
Review schedules and explicitly enable them when ready. Before refreshing a project, select its
actual source on this machine using **Relink source folder/file** on Projects, or:

```powershell
.\scripts\Run-CLI.ps1 --home 'C:\Recovery\Oberhau' relink 1 'C:\Repositories\MyProject'
.\scripts\Run-CLI.ps1 --home 'C:\Recovery\Oberhau' refresh 1
```

Relinking changes the source origin, without discarding saved snapshots or review history.
Refreshing creates a fresh snapshot. ZIP originals must be imported separately. Investigation
continues to use the historical snapshot associated with each stored finding.

## Consistency and limits

An OS file lock excludes scans, imports, refreshes, relinks and other complete backups against the
same data directory while backup captures its research. Scanners inside one scan still run in
parallel. SQLite's online backup captures a consistent database while ordinary review/report
updates can proceed; edits committed after that capture belong to a later backup. The lock is
cooperative: external programs can still alter files. Detected source changes abort backup.

Default limits: 100,000 snapshot file/directory entries, 20 MB per source file, 1 GB database,
4 GB total uncompressed research, and 24 MB manifest. Retained snapshots accumulate; there is no
automatic deletion policy. Restore requires the declared expanded size plus 100 MB of free disk.
Backup stages a complete archive beside its destination and copies it to a newly created file,
so allow room for both staged and final copies. Failed/cancelled work cleans its temporary files.

Archive validation rejects traversal/drive paths, links/junctions, special file entries, Windows
reserved names, case collisions, undeclared/missing files, incorrect sizes/hashes, unsupported
format versions and SQLite schemas, custom triggers/views/indexes, and broken foreign keys.
The completed restored directory is published after validation. Full filesystem TOCTOU hardening
against another process replacing paths during these checks remains a roadmap item.

## Legacy database-only backup

The CLI retains `backup FILE` and `restore FILE NEW_DATABASE_FILE` without `--complete` for
database-only SQLite copies. These do not include or relocate source snapshots, and cannot recover
portable evidence by themselves. Use `--complete` for the research recovery workflow. Restore
accepts exact known SQLite schemas 1–3 and applies only built-in numbered migrations. Complete 0.3.0 bundles (schema 2) were restored and verified with schema 3; unknown/future schemas remain rejected.

Git projects require **Relink Git repository** or `relink-git PROJECT URL --ref BRANCH` before remote refresh after recovery. Previous-snapshot comparison references are relocated too. Scanner histories and advisory links are included in schema 3 backups.
