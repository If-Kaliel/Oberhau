import json
import time
from pathlib import Path
from threading import Event

import pytest

from oberhau.backup import create_backup, restore_backup
from oberhau.core import Cancelled, OberhauError, Status
from oberhau.engine import Engine
from oberhau.framework_analysis import parse_file
from oberhau.research import analyze, research_queue
from oberhau.research_models import EvidenceGraph, ResearchLimits


def analysis(sources):
    cancel = Event()
    deadline = time.monotonic() + 10
    files = {
        path: parse_file(path, "a" * 64, text.encode(), cancel, deadline)
        for path, text in sources.items()
    }
    return analyze(files, ResearchLimits(), cancel, deadline)


@pytest.mark.parametrize(
    "path,code",
    [
        (
            "app/users/route.ts",
            "export async function GET(req: Request, params: any) { const id = params.id; return db.user.findUnique({where:{id}}); }",
        ),
        (
            "Users.java",
            '@RestController class Users { @GetMapping("/{id}") public User get(@PathVariable String id) { return repo.findById(id); } }',
        ),
        (
            "Users.cs",
            '[ApiController] class Users { [HttpGet("{id}")] public object Get(string id) { return db.Users.Find(id); } }',
        ),
    ],
)
def test_resource_paths_are_hypotheses_with_concrete_locations(path, code):
    result = analysis({path: code})
    assert result["endpoints"] == 1
    assert result["hypotheses"][0]["rule"] == "resource-authorization-context"
    hypothesis = result["hypotheses"][0]
    assert hypothesis["inputs"] and hypothesis["confirmation"] and hypothesis["limitations"]
    graph = EvidenceGraph.model_validate(result["graph"])
    nodes = {node.id: node for node in graph.nodes}
    assert all(e in nodes for e in hypothesis["evidence_ids"])
    assert all(nodes[e].path == path for e in hypothesis["execution_path"])
    assert all(nodes[e].sha256 == "a" * 64 for e in hypothesis["execution_path"])


@pytest.mark.parametrize(
    "path,code",
    [
        (
            "app/users/route.ts",
            "export async function GET(req: Request, params: any) { return db.user.findUnique({where:{id:params.id, ownerId:session.user.id}}); }",
        ),
        (
            "Users.java",
            '@RestController class Users { @PreAuthorize("@access.canRead(#id)") @GetMapping("/{id}") public User get(@PathVariable String id) { return repo.findById(id); } }',
        ),
        (
            "Users.cs",
            '[ApiController] class Users { [HttpGet("{id}")] public object Get(string id) { return db.Users.FirstOrDefault(u => u.Id == id && u.OwnerId == User.Id); } }',
        ),
        (
            "app/public/route.ts",
            "export async function GET(req: Request) { return db.post.findMany({where:{published:true}}); }",
        ),
    ],
)
def test_object_controls_and_non_resource_public_lists_are_counterexamples(path, code):
    assert not analysis({path: code})["hypotheses"]


def test_relative_alias_calls_keep_intermediate_evidence_and_gaps():
    result = analysis(
        {
            "app/users/route.ts": 'import {lookup as read} from "../../service"; export async function GET(req: Request, params: any) { return read(params.id); }',
            "service.ts": "export function lookup(id: string) { unknownGuard(id); return db.user.findUnique({where:{id}}); }",
        }
    )
    hypothesis = result["hypotheses"][0]
    assert len(hypothesis["execution_path"]) == 3
    assert any(n["kind"] == "gap" for n in result["graph"]["nodes"])
    assert {
        n["path"] for n in result["graph"]["nodes"] if n["id"] in hypothesis["evidence_ids"]
    } == {"service.ts", "app/users/route.ts"}


@pytest.mark.parametrize(
    "import_line,call,service",
    [
        (
            'import read from "../../service";',
            "read(params.id)",
            "export default function lookup(id: string) { return db.user.findUnique({where:{id}}); }",
        ),
        (
            'import * as api from "../../service";',
            "api.read(params.id)",
            "function lookup(id: string) { return db.user.findUnique({where:{id}}); } export {lookup as read};",
        ),
        (
            'import read from "../../service";',
            "read(params.id)",
            "const lookup = (id:string) => db.user.findUnique({where:{id}}); export default lookup;",
        ),
        (
            'import read from "../../service";',
            "read(params.id)",
            "export default (id:string) => db.user.findUnique({where:{id}});",
        ),
    ],
)
def test_default_namespace_and_export_alias_paths_preserve_both_files(import_line, call, service):
    result = analysis(
        {
            "app/users/route.ts": f"{import_line} export function GET(req: Request, params: any) {{ return {call}; }}",
            "service.ts": service,
        }
    )
    hypothesis = result["hypotheses"][0]
    assert len(hypothesis["execution_path"]) == 3
    assert {
        n["path"] for n in result["graph"]["nodes"] if n["id"] in hypothesis["evidence_ids"]
    } == {"service.ts", "app/users/route.ts"}


@pytest.mark.parametrize(
    "case", ["private", "ambiguous", "shadowed", "reexport", "type-only", "constant"]
)
def test_import_resolution_does_not_invent_executable_paths(case):
    sources = {
        "app/users/route.ts": 'import * as api from "../../service"; export function GET(req: Request, params: any) { return api.lookup(params.id); }',
        "service.ts": "export function lookup(id: string) { return db.user.findUnique({where:{id}}); }",
    }
    if case == "private":
        sources["service.ts"] = sources["service.ts"].replace("export ", "")
    elif case == "ambiguous":
        sources["service.js"] = (
            "export function lookup(id) { return db.user.findUnique({where:{id}}); }"
        )
    elif case == "shadowed":
        sources["app/users/route.ts"] = sources["app/users/route.ts"].replace(
            "params: any", "api: any"
        )
    elif case == "reexport":
        sources["other.ts"] = sources["service.ts"]
        sources["service.ts"] = 'export {lookup} from "./other";'
    elif case == "type-only":
        sources["app/users/route.ts"] = sources["app/users/route.ts"].replace(
            "import *", "import type *"
        )
    elif case == "constant":
        sources["app/users/route.ts"] = sources["app/users/route.ts"].replace(
            "params.id", '"constant-id"'
        )
    result = analysis(sources)
    assert not result["hypotheses"]
    if case != "constant":
        assert any(
            n["kind"] == "gap" and "api.lookup" in n["label"] for n in result["graph"]["nodes"]
        )


def test_server_action_directive_after_comments_and_alias_export():
    result = analysis(
        {
            "action.ts": '// trusted header\n"use server"; function load(id:string) { return db.user.findUnique({where:{id}}); } export {load as read};'
        }
    )
    assert result["endpoints"] == 1
    assert result["hypotheses"][0]["endpoint"] == "Server Action load"
    assert not analysis(
        {
            "action.ts": 'const mode = "use server"; export function load(id:string) { return db.user.findUnique({where:{id}}); }'
        }
    )["endpoints"]


def test_default_wrapper_callbacks_are_not_exported_and_named_expressions_use_the_variable_binding():
    sources = {
        "app/users/route.ts": 'import read from "../../service"; export function GET(req: Request, params: any) { return read(params.id); }',
        "service.ts": "export default withAuth(function internal(id:string) { return db.user.findUnique({where:{id}}); });",
    }
    result = analysis(sources)
    assert not result["hypotheses"]
    assert any(n["kind"] == "gap" and "read" in n["label"] for n in result["graph"]["nodes"])
    sources["service.ts"] = (
        "export const lookup = function internal(id:string) { return db.user.findUnique({where:{id}}); }; export default lookup;"
    )
    assert len(analysis(sources)["hypotheses"]) == 1


def test_python_nested_functions_classes_and_lambdas_are_not_outer_calls():
    summary = parse_file(
        "nested.py",
        "a" * 64,
        b"def outer(value):\n def inner():\n  eval(value)\n class Local:\n  def method(self):\n   exec(value)\n deferred = lambda: open(value)\n print(value)\n",
        Event(),
        time.monotonic() + 5,
    )
    assert [call["name"] for call in summary.symbols[0].calls] == ["print"]


def test_inconsistent_route_policy_compares_same_operation_not_arbitrary_endpoints():
    result = analysis(
        {
            "Users.java": '@RestController class Users { @PreAuthorize("hasRole(ADMIN)") @GetMapping("/private") public Object privateList() { return repo.findAll(); } @GetMapping("/public") public Object publicList() { return repo.findAll(); } @GetMapping("/other") public Object other() { return unrelated.load(); } }'
        }
    )
    assert len(result["hypotheses"]) == 1
    assert result["hypotheses"][0]["rule"] == "access-policy-inconsistency"
    assert any(e["relation"] == "supports-review-question" for e in result["graph"]["edges"])


def test_external_policies_and_bad_syntax_do_not_disappear():
    result = analysis(
        {
            "app/users/route.ts": "export function GET(req: Request, params: any) { return db.user.findUnique({where:{id:params.id}}); }",
            "middleware.ts": "export function middleware(req: Request) { return authenticate(req); }",
        }
    )
    assert any(c["kind"] == "middleware-candidate" for c in result["hypotheses"][0]["controls"])
    assert result["hypotheses"][0]["confidence"] < 0.7
    assert not analysis({"app/users/route.ts": "export function GET( {{{"})["hypotheses"]


def test_minimal_api_authorization_is_indexed():
    result = analysis(
        {
            "Program.cs": 'app.MapGet("/users/{id}", (string id) => db.Users.Find(id)).RequireAuthorization("admin");'
        }
    )
    assert result["endpoints"] == 1
    endpoint = next(n for n in result["graph"]["nodes"] if n["kind"] == "endpoint")
    assert "MapGet" in endpoint["label"]
    assert any(n["kind"] == "control" for n in result["graph"]["nodes"])


def test_multiple_routes_on_one_line_keep_distinct_execution_endpoint_nodes():
    result = analysis(
        {
            "app/users/route.ts": "export function GET(req: Request, params: any) { return db.user.findUnique({where:{id:params.id}}); } export function POST(req: Request, params: any) { return db.user.findUnique({where:{id:params.id}}); }"
        }
    )
    nodes = {node["id"]: node for node in result["graph"]["nodes"]}
    assert len(result["hypotheses"]) == 2
    for hypothesis in result["hypotheses"]:
        entry = nodes[hypothesis["execution_path"][0]]
        assert entry["kind"] == "endpoint" and entry["label"].startswith(
            hypothesis["endpoint"] + " | "
        )
    assert len({h["execution_path"][0] for h in result["hypotheses"]}) == 2


def test_real_pipeline_cache_history_review_and_portable_graph(engine, tmp_path):
    source = tmp_path / "sources"
    (source / "app/users").mkdir(parents=True)
    route = source / "app/users/route.ts"
    route.write_text(
        "export function GET(req: Request, params: any) { return db.user.findUnique({where:{id:params.id}}); }"
    )
    (source / "never.py").write_text('raise RuntimeError("Imported code must not execute")')
    project = engine.ingestion.add(source, "Authorized fixture")
    first = engine.scan(project, "research")
    run = engine.db.query("SELECT * FROM research_runs")[0]
    assert run["status"] == "completed"
    data = json.loads(run["data"])
    assert data["index"]["parsed"] == 2 and data["index"]["reused"] == 0
    assert engine.db.scanner_runs(first)[0]["scanner"] == "contextual"
    finding = engine.db.query(
        "SELECT id FROM findings WHERE json_extract(data,'$.scanner')='contextual'"
    )[0]["id"]
    engine.db.review(
        finding, Status.FALSE_POSITIVE, "Synthetic route intended public; human decision"
    )
    queue = research_queue(engine.db, project)
    assert queue[0]["status"] == Status.FALSE_POSITIVE and queue[0]["priority"] < 0
    engine.scan(project, "research")
    repeated = json.loads(
        engine.db.query("SELECT data FROM research_runs ORDER BY id DESC")[0]["data"]
    )
    assert repeated["index"]["parsed"] == 0 and repeated["index"]["reused"] == 2
    assert repeated["changes"][0]["state"] == "previously-observed"
    assert engine.db.finding(finding)["status"] == Status.FALSE_POSITIVE
    bundle = tmp_path / "research.zip"
    create_backup(engine.db, engine.home, bundle)
    recovered = tmp_path / "recovered"
    restore_backup(bundle, recovered)
    restored = Engine(recovered)
    assert (
        json.loads(restored.db.query("SELECT data FROM research_runs ORDER BY id DESC")[0]["data"])[
            "graph"
        ]
        == repeated["graph"]
    )
    assert restored.investigate(finding)["source_unchanged"]
    route.write_text(
        "export function GET(req: Request, params: any) { return db.user.findUnique({where:{id:params.id, ownerId:session.user.id}}); }"
    )
    engine.refresh_project(project)
    engine.scan(project, "research")
    latest = json.loads(
        engine.db.query("SELECT data FROM research_runs ORDER BY id DESC")[0]["data"]
    )
    assert latest["index"]["parsed"] == 1 and latest["index"]["reused"] == 1
    assert latest["changes"][0]["state"] == "no-longer-observed"
    assert engine.db.finding(finding)["status"] == Status.FALSE_POSITIVE


def test_limits_and_cancel_fail_explicitly_without_conclusions():
    files = {
        "app/users/route.ts": parse_file(
            "app/users/route.ts",
            "a" * 64,
            b"export function GET(req: Request) { db.user.findMany(); }",
            Event(),
            time.monotonic() + 10,
        )
    }
    cancel = Event()
    cancel.set()
    with pytest.raises(Cancelled):
        analyze(files, ResearchLimits(), cancel, time.monotonic() + 10)
    with pytest.raises(OberhauError, match="deadline"):
        analyze(files, ResearchLimits(), Event(), time.monotonic() - 1)


def test_research_rejects_changed_snapshot(engine, tmp_path, monkeypatch):
    source = tmp_path / "route.ts"
    source.write_text("export function GET(req: Request) { return db.user.findMany(); }")
    project = engine.ingestion.add(source, "Integrity fixture")
    from oberhau.research import run_research

    original = run_research

    def alter(engine, row, *args):
        (Path(row["root"]) / "route.ts").write_text("modified after indexing")
        return original(engine, row, *args)

    monkeypatch.setattr("oberhau.research.run_research", alter)
    scan = engine.scan(project, "research")
    assert engine.db.query("SELECT status FROM scans WHERE id=?", (scan,))[0]["status"] == "failed"
    assert engine.db.query("SELECT status FROM research_runs")[0]["status"] == "failed"
    assert not engine.db.query("SELECT id FROM findings")


def test_constant_intermediate_arguments_and_comment_policies_are_handled_conservatively():
    result = analysis(
        {
            "app/lookup/route.ts": 'import {lookup} from "../../service"; export function GET(req: Request) { return lookup("id"); }',
            "service.ts": "export function lookup(id: string) { return db.user.findUnique({where:{id}}); }",
        }
    )
    assert not result["hypotheses"]
    result = analysis(
        {
            "Users.java": '@RestController class Users { /* @PreAuthorize("@access.check(#id)") */ @GetMapping("/{id}") public Object read(String id) { return repo.findById(id); } }'
        }
    )
    assert result["hypotheses"] and not result["hypotheses"][0]["controls"]


def test_python_slice_retains_branch_alternatives_and_sanitizer_uncertainty():
    from oberhau.python_analysis import source_trace

    result = source_trace(
        'import html\ndef route(value, flag):\n    query = value\n    if flag:\n        query = "constant"\n    db.execute(html.escape(query))\n',
        6,
        "python-sql-format",
    )
    assert result["analysis_gaps"]
    assert any(s["expression"] == "value" for s in result["sources"])
    assert result["sanitizers"][0]["operation"] == "html.escape"
    assert result["conditional_checks"]
