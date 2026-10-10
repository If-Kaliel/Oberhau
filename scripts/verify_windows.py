"""Native release QA with a system-only PATH and fresh owned demonstration data."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from oberhau import __version__  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "dist/Oberhau"


def main():
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC"}
    }
    environment["PATH"] = str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32")
    for key in ("PYTHONHOME", "PYTHONPATH", "QT_QPA_PLATFORM"):
        environment.pop(key, None)
    workspace = (ROOT / ".oberhau").resolve()
    if not workspace.is_relative_to(ROOT.resolve()):
        raise RuntimeError("QA data must remain within the workspace")
    workspace.mkdir(exist_ok=True)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="windows-qa-", dir=workspace) as temporary:
        temporary = Path(temporary)
        for key, name in [
            ("TEMP", "temp"),
            ("TMP", "temp"),
            ("LOCALAPPDATA", "localappdata"),
            ("APPDATA", "appdata"),
            ("USERPROFILE", "user"),
        ]:
            path = temporary / name
            path.mkdir(exist_ok=True)
            environment[key] = str(path)
        archive = ROOT / "artifacts" / f"Oberhau-{__version__}-windows-x64.zip"
        destination = temporary / "extracted"
        with zipfile.ZipFile(archive) as source:
            # Release archive was generated locally; still reject traversal before extraction.
            for member in source.infolist():
                if (
                    not (destination / member.filename)
                    .resolve()
                    .is_relative_to(destination.resolve())
                ):
                    raise RuntimeError("Release archive path escapes extraction directory")
            source.extractall(destination)
        bundle = destination / "Oberhau"
        manifest = json.loads((bundle / "MANIFEST.json").read_text())
        assert manifest["version"] == __version__
        for name, expected in manifest["files"].items():
            path = bundle / name
            assert path.stat().st_size == expected["bytes"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == expected["sha256"]
        home = Path(temporary) / "cli"

        def run(binary, arguments):
            completed = subprocess.run(
                [str(bundle / binary), *map(str, arguments)],
                env=environment,
                cwd=temporary,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if completed.returncode:
                raise RuntimeError(
                    f"{binary} QA failed: {completed.stdout[:2000]} {completed.stderr[:2000]}"
                )
            return completed

        def cli(*arguments):
            return json.loads(run("oberhau-cli.exe", ["--home", home, *arguments]).stdout)

        source = Path(temporary) / "source"
        (source / "app/users").mkdir(parents=True)
        (source / "app/users/route.ts").write_text(
            'import read from "../../service"; export function GET(req: Request, params: any) { return read(params.id); }'
        )
        (source / "service.ts").write_text(
            "export default function lookup(id: string) { return db.user.findUnique({where:{id}}); }"
        )
        project = cli("add", source, "--name", "DEMONSTRATION / FROZEN DEFAULT IMPORT")["project"]
        scan = cli("scan", project, "--profile", "research")["id"]
        with closing(sqlite3.connect(home / "oberhau.sqlite3")) as connection:
            run_id, status = connection.execute(
                "SELECT id,status FROM research_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        details = cli("research-details", run_id)
        assert status == "completed" and len(details["hypotheses"]) == 1
        assert details["index"]["parser_memory"]["enforced"]
        assert len(cli("research-queue", "--project", project)) == 1
        assistant = cli("research-assist", run_id)
        cache_preview = cli("maintenance")
        assert not cache_preview["applied"] and cache_preview["before"]["runs"] == 1
        cache_clean = cli("maintenance", "--apply")
        assert cache_clean["applied"] and cli("research-details", run_id)["hypotheses"]
        export_controls = []
        for label, code, expected in [
            (
                "wrapped callback",
                "export default withAuth(function internal(id:string) { return db.user.findUnique({where:{id}}); });",
                0,
            ),
            (
                "named function expression",
                "export const lookup = function internal(id:string) { return db.user.findUnique({where:{id}}); }; export default lookup;",
                1,
            ),
        ]:
            (source / "service.ts").write_text(code)
            cli("refresh", project)
            cli("scan", project, "--profile", "research")
            with closing(sqlite3.connect(home / "oberhau.sqlite3")) as connection:
                latest, latest_status = connection.execute(
                    "SELECT id,status FROM research_runs ORDER BY id DESC LIMIT 1"
                ).fetchone()
            found = cli("research-details", latest)
            assert latest_status == "completed" and len(found["hypotheses"]) == expected
            export_controls.append(
                {"case": label, "hypotheses": len(found["hypotheses"]), "status": latest_status}
            )
        benchmark = cli("benchmark")
        assert len(benchmark["cases"]) == 12 and benchmark["parser_memory"]["enforced"]
        labs = [cli("local-lab", recipe) for recipe in ("authorization", "input-validation")]
        assert all(result["passed"] for result in labs)
        backup = Path(temporary) / "backup.zip"
        minified = Path(temporary) / "minified"
        minified.mkdir()
        (minified / "route.ts").write_text(
            "export function GET(req: Request, params: any) { return db.user.findUnique({where:{id:params.id}}); } export function POST(req: Request, params: any) { return db.user.findUnique({where:{id:params.id}}); }"
        )
        minified_project = cli("add", minified, "--name", "DEMONSTRATION / FROZEN GRAPH IDENTITY")[
            "project"
        ]
        cli("scan", minified_project, "--profile", "research")
        with closing(sqlite3.connect(home / "oberhau.sqlite3")) as connection:
            latest = connection.execute(
                "SELECT id FROM research_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()[0]
        minified_data = cli("research-details", latest)
        nodes = {node["id"]: node for node in minified_data["graph"]["nodes"]}
        assert len(minified_data["hypotheses"]) == 2
        for hypothesis in minified_data["hypotheses"]:
            assert nodes[hypothesis["execution_path"][0]]["label"].startswith(
                hypothesis["endpoint"] + " | "
            )
        cli("backup", backup, "--complete")
        restored = Path(temporary) / "restored"
        cli("restore", backup, restored, "--complete")
        migrations = []
        for version in ("0.4.0", "0.5.1"):
            previous_release = ROOT / "artifacts" / f"Oberhau-{version}-windows-x64.zip"
            if not previous_release.exists():
                migrations.append(
                    {
                        "from": version,
                        "status": "not executed; previous release artifact unavailable",
                    }
                )
                continue
            old_destination = temporary / ("old-" + version)
            with zipfile.ZipFile(previous_release) as archive_source:
                for member in archive_source.infolist():
                    if (
                        not (old_destination / member.filename)
                        .resolve()
                        .is_relative_to(old_destination.resolve())
                    ):
                        raise RuntimeError("Previous archive escapes QA directory")
                archive_source.extractall(old_destination)
            legacy_home = temporary / ("data-" + version)

            def old_cli(*arguments, old_destination=old_destination, legacy_home=legacy_home):
                return json.loads(
                    run(
                        str(old_destination / "Oberhau/oberhau-cli.exe"),
                        ["--home", legacy_home, *arguments],
                    ).stdout
                )

            old_cli("demo")
            old_cli(
                "review",
                1,
                "--status",
                "False Positive",
                "--notes",
                "DEMONSTRATION / preserved migration decision",
            )
            legacy_report = temporary / ("report-" + version + ".md")
            old_cli("report", 1, "--output", legacy_report)
            before = old_cli("metrics")
            upgraded = json.loads(run("oberhau-cli.exe", ["--home", legacy_home, "metrics"]).stdout)
            assert upgraded["projects"] == before["projects"] == 1
            assert upgraded["reports"] == before["reports"] == 1
            investigated = json.loads(
                run("oberhau-cli.exe", ["--home", legacy_home, "investigate", 1]).stdout
            )
            assert investigated["status"] == "False Positive" and investigated["source_unchanged"]
            assert investigated["notes"] == "DEMONSTRATION / preserved migration decision"
            with closing(sqlite3.connect(legacy_home / "oberhau.sqlite3")) as connection:
                assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
            migrations.append(
                {
                    "from": version,
                    "status": "passed",
                    "schema": 4,
                    "project_reports_reviews_evidence_preserved": True,
                }
            )
        gui_results = {}
        for mode, flag in [("desktop", "--smoke"), ("research", "--smoke-research")]:
            screenshot = ROOT / "artifacts" / f"oberhau-{__version__}-frozen-{mode}.png"
            run("Oberhau.exe", ["--home", Path(temporary) / mode, flag, screenshot])
            gui_results[mode] = json.loads(screenshot.with_suffix(".json").read_text())
        result = {
            "system_only_path": True,
            "extracted_release": str(archive),
            "fresh_environment": True,
            "manifest_files_verified": len(manifest["files"]),
            "limitations": "Fresh extraction, application data and restricted environment on the existing Windows host; not a newly installed OS or clean virtual machine.",
            "seconds": time.monotonic() - started,
            "project": project,
            "scan": scan,
            "research": {
                "status": status,
                "index": details["index"],
                "hypotheses": len(details["hypotheses"]),
            },
            "assistant": assistant["generator"],
            "export_controls": export_controls,
            "minified_routes": len(minified_data["hypotheses"]),
            "benchmark": benchmark,
            "labs_passed": all(r["passed"] for r in labs),
            "backup_restore": restored.is_dir(),
            "migrations": migrations,
            "gui": gui_results,
            "executables": {
                name: hashlib.sha256((bundle / name).read_bytes()).hexdigest()
                for name in ("Oberhau.exe", "oberhau-cli.exe")
            },
        }
    output = ROOT / f"artifacts/oberhau-{__version__}-frozen-verification.json"
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "verification": str(output),
                "seconds": result["seconds"],
                "research": result["research"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
