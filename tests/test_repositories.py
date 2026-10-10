import json
import shutil
import sys
from pathlib import Path
from threading import Event

import pytest

from oberhau.backup import create_backup, restore_backup
from oberhau.core import Cancelled, Limits, OberhauError
from oberhau.engine import Engine
from oberhau.repositories import repository_ref, repository_url
from oberhau.security import ProcessRunner


@pytest.fixture
def git_source(tmp_path, monkeypatch):
    binary = shutil.which("git")
    if not binary:
        pytest.skip("A trusted Git executable is required for native Git fixtures")
    profile = tmp_path / "fixture-profile"
    profile.mkdir()
    (profile / "empty.config").write_text("")
    source = tmp_path / "fixture-repository"
    source.mkdir()
    runner = ProcessRunner(Limits(timeout=30), {"git": binary}, git_home=profile)

    def git(*args):
        return runner.run("git", ["-c", "core.hooksPath=", *args], source, Event()).strip()

    git("init", "-b", "main")
    (source / "app.py").write_bytes(b"eval(user_input)\n")
    (source / ".gitattributes").write_text("app.py filter=must_not_run eol=crlf\n")
    marker = tmp_path / "executed-imported-code"
    (source / "never.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n"
    )

    def commit():
        git("add", ".")
        git(
            "-c",
            "user.name=Oberhau fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "Local regression commit",
        )
        return git("rev-parse", "HEAD")

    first = commit()
    original = ProcessRunner.run

    def local_transport(self, tool, args, cwd, cancel, *extra, **kwargs):
        if tool == "git" and "clone" in args:
            args = list(args)
            position = args.index("--") + 1
            assert args[position] == "https://github.com/fixture/example.git"
            args[position] = source.as_uri()
            args[args.index("protocol.file.allow=never")] = "protocol.file.allow=always"
        return original(self, tool, args, cwd, cancel, *extra, **kwargs)

    # Only the test transport maps the already-validated public URL to this owned fixture.
    monkeypatch.setattr(ProcessRunner, "run", local_transport)
    return source, first, commit, marker


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "file:///C:/repo",
        "ssh://github.com/a/b",
        "https://github.com.evil.test/a/b",
        "https://user:secret@github.com/a/b",
        "https://github.com/a/b?access_token=fake",
        "https://github.com/a/b/tree/main",
        "https://github.com/a/%2e%2e",
        "https://github.com:444/a/b",
        "https://localhost/a/b",
    ],
)
def test_repository_url_boundaries(url):
    with pytest.raises(OberhauError):
        repository_url(url)


@pytest.mark.parametrize(
    "ref",
    [
        "--upload-pack=evil",
        "../../outside",
        "main.lock",
        "a//b",
        "a@{0}",
        "main\ncommand",
        "a:b",
        "/main",
    ],
)
def test_repository_ref_boundaries(ref):
    with pytest.raises(OberhauError):
        repository_ref(ref)


def test_native_git_import_refresh_diff_and_portable_recovery(
    engine, git_source, tmp_path, monkeypatch
):
    source, first, commit, marker = git_source
    evil = tmp_path / "inherited.gitconfig"
    evil.write_text(
        '[filter "must_not_run"]\n\tsmudge = command-that-must-never-run\n\trequired = true\n[credential]\n\thelper = command-that-must-never-run\n'
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(evil))
    project = engine.repositories().add(
        "https://github.com/fixture/example", "Git fixture", ref="main"
    )
    row = engine.ingestion.project(project)
    metadata = json.loads(row["metadata"])
    assert metadata["commit"] == first and metadata["git_tree_files"] == 3
    assert row["origin"] == "https://github.com/fixture/example.git"
    assert (Path(row["root"]) / "app.py").read_bytes() == b"eval(user_input)\n"
    assert not (Path(row["root"]) / ".git").exists()
    assert not marker.exists()
    engine.scan(project, "quick")
    finding = engine.db.query("SELECT id FROM findings")[0]["id"]
    (source / "app.py").write_bytes(b"print('corrected')\n")
    second = commit()
    engine.refresh_project(project)
    metadata = json.loads(engine.ingestion.project(project)["metadata"])
    assert metadata["commit"] == second and metadata["previous_commit"] == first
    assert metadata["changes"]["counts"] == {"added": 0, "removed": 0, "modified": 1}
    result = engine.compare_source(project, "app.py")
    assert (
        result["source_integrity"]
        and "-eval(user_input)" in result["diff"]
        and "+print('corrected')" in result["diff"]
    )
    assert engine.investigate(finding)["source_unchanged"]
    target, home = tmp_path / "git.zip", tmp_path / "recovered-git"
    create_backup(engine.db, engine.home, target)
    restore_backup(target, home)
    recovered = Engine(home)
    assert recovered.compare_source(project, "app.py")["diff"] == result["diff"]
    with pytest.raises(OberhauError, match="relinked"):
        recovered.refresh_project(project)
    recovered.repositories().relink(project, "https://github.com/fixture/example", ref="main")
    recovered.refresh_project(project)
    assert not marker.exists()


def test_git_cancellation_leaves_no_partial_project(engine, git_source):
    cancel = Event()

    def progress(message):
        if message.startswith("Verified 1/"):
            cancel.set()

    with pytest.raises(Cancelled):
        engine.repositories().add(
            "https://github.com/fixture/example", "Cancelled", cancel=cancel, progress=progress
        )
    assert not engine.db.query("SELECT id FROM projects")
    assert not list((engine.home / "projects").iterdir())
    assert not list((engine.home / "tmp").glob("oberhau-git-*"))


@pytest.mark.parametrize(
    "entry",
    [
        "120000 blob " + "0" * 40 + " 4\tlink\0",
        "160000 commit " + "0" * 40 + " -\tmodule\0",
        "100644 blob " + "0" * 40 + " 4\t../escape\0",
        "100644 blob " + "0" * 40 + " 4\tNUL\0",
        "100644 blob " + "0" * 40 + " 2000001\tlarge.py\0",
    ],
)
def test_git_tree_types_paths_and_sizes(engine, tmp_path, entry):
    with pytest.raises(OberhauError):
        engine.repositories().validate_tree(entry, tmp_path)


def test_git_directory_case_collision(engine, tmp_path):
    payload = (
        "100644 blob " + "0" * 40 + " 1\tSrc/a.py\0" + "100644 blob " + "0" * 40 + " 1\tsrc/b.py\0"
    )
    with pytest.raises(OberhauError, match="collide"):
        engine.repositories().validate_tree(payload, tmp_path)


@pytest.mark.parametrize(
    "paths", [("file.py", "file.py"), ("src", "src/a.py"), ("src/a.py", "src")]
)
def test_git_duplicate_and_file_directory_collisions(engine, tmp_path, paths):
    payload = "".join("100644 blob " + "0" * 40 + f" 1\t{path}\0" for path in paths)
    with pytest.raises(OberhauError, match="conflicting"):
        engine.repositories().validate_tree(payload, tmp_path)


def test_native_process_staging_quota_is_enforced(tmp_path):
    runner = ProcessRunner(Limits(timeout=5), {"fixture": sys.executable})
    with pytest.raises(OberhauError, match="staging exceeds"):
        runner.run(
            "fixture",
            ["-c", "from pathlib import Path; Path('owned.bin').write_bytes(b'x'*1500)"],
            tmp_path,
            Event(),
            disk_root=tmp_path,
            max_disk_bytes=1000,
        )


def test_local_refresh_diff_redacts_source_secrets(engine, tmp_path):
    source = tmp_path / "local.py"
    source.write_text('password = "fabricated_fixture_value_one"\n')
    project = engine.ingestion.add(source, "Local diff")
    source.write_text('password = "fabricated_fixture_value_two"\nprint("new")\n')
    engine.refresh_project(project)
    result = engine.compare_source(project, "local.py")
    assert result["source_integrity"] and "+print" in result["diff"]
    assert "fabricated_fixture" not in result["diff"]
