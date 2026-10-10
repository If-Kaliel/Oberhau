import json
from threading import Event

import pytest

from oberhau.cli import main
from oberhau.core import Cancelled, OberhauError, Status
from oberhau.reporting import generate, report_evidence
from oberhau.research_assistant import ResearchQuery, ResearchTools, assist


@pytest.fixture
def contextual(engine, tmp_path):
    source = tmp_path / "app/users"
    source.mkdir(parents=True)
    (source / "route.ts").write_text(
        'import {lookup} from "./service"; export function GET(req: Request, params: any) { return lookup(params.id); }'
    )
    (source / "service.ts").write_text(
        "export function lookup(id: string) { return db.user.findUnique({where:{id}}); }"
    )
    project = engine.ingestion.add(source, "Research fixture")
    engine.scan(project, "research")
    run = engine.db.query("SELECT id FROM research_runs")[0]["id"]
    return project, run


def test_structured_queries_and_source_integrity(engine, contextual):
    tools = ResearchTools(engine, contextual[1])
    summary = tools.summarize()
    assert summary["evidence"]
    assert len(json.dumps(summary).encode()) < 6500
    for action in ("symbols", "locate_function", "scanner_results", "git_changes"):
        assert isinstance(tools.execute(ResearchQuery(action=action)), dict)
    source = next(n for n in tools.graph.nodes if n.kind == "operation")
    result = tools.execute(ResearchQuery(action="excerpt", evidence_id=source.id))
    assert "findUnique" in result["excerpt"]
    assert tools.execute(ResearchQuery(action="calls", evidence_id=source.id))["relations"]
    (tools.root / source.path).write_text("changed")
    with pytest.raises(OberhauError, match="integrity"):
        tools.execute(ResearchQuery(action="excerpt", evidence_id=source.id))


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "execute", "name": "whoami"},
        {"action": "excerpt", "path": "../outside"},
        {"action": "symbols", "command": "delete"},
    ],
)
def test_no_command_or_path_interface(payload):
    with pytest.raises(ValueError):
        ResearchQuery.model_validate(payload)


def test_unknown_evidence_cannot_read_files(engine, contextual):
    tools = ResearchTools(engine, contextual[1])
    with pytest.raises(OberhauError):
        tools.execute(ResearchQuery(action="excerpt", evidence_id="unknown"))
    with pytest.raises(OberhauError):
        tools.symbols_for_file("../outside")
    with pytest.raises(OberhauError):
        ResearchTools(engine, 999999)


def test_historical_symbol_cache_uses_the_recorded_analyzer_version(engine, contextual):
    tools = ResearchTools(engine, contextual[1])
    tools.data["index"]["version"] = "retained-old-version"
    engine.db.execute("UPDATE research_files SET version='retained-old-version'")
    assert tools.symbols_for_file("service.ts").symbols[0].name == "lookup"


def test_scan_cli_keeps_progress_on_stderr_and_stdout_as_a_complete_json_record(
    engine, contextual, capsys
):
    assert (
        main(["--home", str(engine.home), "scan", str(contextual[0]), "--profile", "research"]) == 0
    )
    result = capsys.readouterr()
    assert json.loads(result.out)["status"] == "completed"
    assert "Contextual research" in result.err


class FakeModel:
    model = "qwen3.5:4b"

    def __init__(self, steps):
        self.steps = steps
        self.requests = []

    def request(self, path, body, cancel):
        self.requests.append(body)
        return {"message": {"content": json.dumps(self.steps.pop(0))}}


def test_assistant_queries_then_cites_consulted_evidence_without_upgrading_findings(
    engine, contextual
):
    tools = ResearchTools(engine, contextual[1])
    eid = tools.summarize()["evidence"][0]["id"]
    model = FakeModel(
        [
            {
                "queries": [{"action": "excerpt", "evidence_id": eid}],
                "claims": [],
                "questions": ["Does middleware enforce ownership?"],
                "limitations": "Need code context",
            },
            {
                "queries": [],
                "claims": [
                    {
                        "kind": "hypothesis",
                        "text": "Object authorization requires review",
                        "evidence_ids": [eid],
                    }
                ],
                "questions": ["Which policy applies?"],
                "limitations": "Runtime behavior unverified",
            },
        ]
    )
    before = engine.db.query("SELECT status,data FROM findings")
    result = assist(engine, contextual[1], True, client=model)
    assert result["generator"] == "ollama:unverified-research"
    assert len(result["trace"]) == 1 and len(result["claims"]) == 1
    assert len(model.requests) == 2
    assert all(r["keep_alive"] == 0 and r["think"] is False for r in model.requests)
    assert (
        eid
        in model.requests[0]["format"]["$defs"]["ResearchClaim"]["properties"]["evidence_ids"][
            "items"
        ]["enum"]
    )
    assert engine.db.query("SELECT status,data FROM findings") == before
    assert engine.db.query("SELECT status FROM research_assistance")[0]["status"] == "provisional"


@pytest.mark.parametrize(
    "claim",
    [
        {"kind": "hypothesis", "text": "Maybe unsafe", "evidence_ids": ["fabricated"]},
        {"kind": "confirmed", "text": "Proven", "evidence_ids": ["fabricated"]},
    ],
)
def test_unseen_citations_and_invalid_claim_types_fall_back(engine, contextual, claim):
    result = assist(
        engine,
        contextual[1],
        True,
        client=FakeModel(
            [{"queries": [], "claims": [claim], "questions": [], "limitations": "None"}]
        ),
    )
    assert result["generator"] == "deterministic:fallback" and not result["claims"]


def test_ai_is_optional_and_cancelled_queries_do_not_run(engine, contextual):
    assert assist(engine, contextual[1])["generator"] == "deterministic"
    cancel = Event()
    cancel.set()
    with pytest.raises(Cancelled):
        assist(engine, contextual[1], True, cancel, client=FakeModel([]))
    with pytest.raises(OberhauError):
        assist(engine, contextual[1], iterations=4)


def test_cli_queue_details_assistant_and_report_check_cross_file_evidence(
    engine, contextual, capsys
):
    prefix = ["--home", str(engine.home)]
    assert main(prefix + ["research-queue", "--project", str(contextual[0])]) == 0
    assert json.loads(capsys.readouterr().out)[0]["evidence_quality"] == "referenced-path"
    assert main(prefix + ["research-details", str(contextual[1])]) == 0
    assert json.loads(capsys.readouterr().out)["graph"]["nodes"]
    assert main(prefix + ["research-assist", str(contextual[1])]) == 0
    assert json.loads(capsys.readouterr().out)["generator"] == "deterministic"
    finding = engine.db.query(
        "SELECT id FROM findings WHERE json_extract(data,'$.scanner')='contextual'"
    )[0]["id"]
    engine.db.review(finding, Status.VERIFIED, "Synthetic human-review regression")
    assert report_evidence(engine.db, finding)["ready_for_human_review"]
    record = engine.db.finding(finding)["finding"]
    from pathlib import Path

    (Path(record.evidence["snapshot"]) / "service.ts").write_text("changed")
    assert report_evidence(engine.db, finding)["source_integrity"] == "changed"
    _, report = generate(engine.db, finding)
    assert "Evidence incomplete" in report


def test_changed_helper_reopens_historical_human_review_even_with_same_endpoint(engine, contextual):
    project, _ = contextual
    row = engine.db.query(
        "SELECT id FROM findings WHERE json_extract(data,'$.scanner')='contextual'"
    )[0]
    engine.db.review(row["id"], Status.VERIFIED, "Reviewed the initial helper implementation")
    before = engine.db.finding(row["id"])["finding"].evidence["source_sha256"]
    source = engine.ingestion.project(project)["origin"]
    from pathlib import Path

    (Path(source) / "service.ts").write_text(
        "export function lookup(id: string) { audit(id); return db.user.findUnique({where:{id}}); }"
    )
    engine.refresh_project(project)
    engine.scan(project, "research")
    record = engine.db.finding(row["id"])
    assert record["finding"].evidence["source_sha256"] == before
    assert record["status"] == Status.SUSPECTED
    assert not report_evidence(engine.db, row["id"])["ready_for_human_review"]
