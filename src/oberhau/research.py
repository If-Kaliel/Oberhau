"""Offline contextual research, incremental syntax cache and review queue."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import time
from pathlib import PurePosixPath
from threading import Event

from oberhau.core import Cancelled, Finding, OberhauError, Status, now
from oberhau.framework_analysis import EXTENSIONS, PARSER_VERSION, checkpoint
from oberhau.parser_isolation import ParserFileError, ParserSession
from oberhau.research_models import FileSummary, GraphBuilder, Hypothesis, ResearchLimits
from oberhau.security import confined, sanitize

LIMITATIONS = [
    "Syntax observations do not prove runtime bindings, dominance, reachability or attacker control",
    "Only unique same-file direct calls and relative named/default/namespace JavaScript imports to indexed exports are followed",
    "Dynamic dispatch, dependency implementations and Java/C# service receiver bindings are unresolved",
    "Global middleware, filters, inherited policies and infrastructure may supply additional protections",
    "Absence of visible controls is a research question, never a vulnerability verdict",
]
PARSER_CONTROL = "oberhau-parser-control.py"
CONFIRMATION = [
    "Resolve middleware/filter/security configuration and policy activation",
    "Establish trusted identity and intended resource access policy",
    "Trace bindings and feasible paths with authorized local synthetic fixtures",
    "Human review of expected versus observed behavior before any external test or report",
]


def resolve_call(symbol, call, files, by_name):
    name = call["name"]
    root_name = name.split(".")[0]
    if root_name in symbol.parameters or any(
        t["target"] == root_name and t["line"] <= call["line"] for t in symbol.transformations
    ):
        return None
    if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?", name):
        imported = files[symbol.path].imports.get(root_name)
        if imported and imported["module"].startswith("."):
            namespace = imported["name"] == "*"
            if ("." in name) != namespace:
                return None
            export_name = name.split(".")[-1] if namespace else imported["name"]
            base = posixpath.normpath(
                posixpath.join(posixpath.dirname(symbol.path), imported["module"])
            )
            candidates = [
                base,
                *(base + ext for ext in (".ts", ".tsx", ".js", ".jsx")),
                base + "/index.ts",
                base + "/index.js",
            ]
            matches = [
                s
                for candidate in candidates
                if candidate in files
                for s in by_name.get(files[candidate].exports.get(export_name, ""), [])
                if s.path == candidate and not s.owner
            ]
        else:
            if imported or "." in name:
                return None
            matches = [s for s in by_name.get(name, []) if s.path == symbol.path and not s.owner]
        return matches[0] if len(matches) == 1 else None
    return None


def analyze(
    files: dict[str, FileSummary],
    limits: ResearchLimits,
    cancel: Event,
    deadline: float,
    project_label="project",
    commit="",
) -> dict:
    graph = GraphBuilder(limits.max_nodes)
    project_node = graph.add("project", project_label)
    if commit:
        commit_node = graph.add("commit", commit)
        graph.link(project_node, commit_node, "snapshot-at")
    symbols = [s for file in files.values() for s in file.symbols]
    if len(symbols) > limits.max_symbols:
        raise OberhauError("Project symbol budget exceeded")
    by_name = {}
    symbol_ids = {}
    ambient = []
    file_ids = {}
    for file in files.values():
        file_id = file_ids[file.path] = graph.add("file", file.path, file.path, sha256=file.sha256)
        graph.link(project_node, file_id, "contains")
        for control in file.ambient_controls:
            control = {**control, "path": file.path}
            ambient.append(control)
            cid = graph.add(
                "control", control["name"], file.path, control["line"], file.sha256, control["code"]
            )
            graph.link(file_id, cid, "possible-external-protection")
    for symbol in symbols:
        by_name.setdefault(symbol.name, []).append(symbol)
        qualified = f"{symbol.owner}.{symbol.name}" if symbol.owner else symbol.name
        sid = graph.add(
            "endpoint" if symbol.endpoint else "function",
            f"{symbol.endpoint} | {qualified}" if symbol.endpoint else qualified,
            symbol.path,
            symbol.line,
            files[symbol.path].sha256,
        )
        symbol_ids[(symbol.path, symbol.line, symbol.name, symbol.owner)] = sid
        graph.link(file_ids[symbol.path], sid, "defines")
    paths = []
    for endpoint in [s for s in symbols if s.endpoint]:
        checkpoint(cancel, deadline)
        visited = 0

        def visit(symbol, chain, controls, stack, depth, influenced, endpoint=endpoint):
            nonlocal visited
            checkpoint(cancel, deadline)
            visited += 1
            sid = symbol_ids[(symbol.path, symbol.line, symbol.name, symbol.owner)]
            if visited > limits.max_visits or depth > limits.max_depth or sid in stack:
                gap = graph.add(
                    "gap",
                    "Call traversal limit or recursion: analysis interrupted",
                    symbol.path,
                    symbol.line,
                )
                graph.link(chain[-1], gap, "unresolved")
                return
            controls = [*controls, *({**c, "path": symbol.path} for c in symbol.controls)]
            control_ids = []
            for control in symbol.controls:
                cid = graph.add(
                    "control",
                    control["kind"] + ": " + control["name"],
                    symbol.path,
                    control["line"],
                    files[symbol.path].sha256,
                    control["code"],
                )
                graph.link(sid, cid, "observes-control-not-dominance")
                control_ids.append(cid)
            sources = []
            for source in symbol.sources:
                source_id = graph.add(
                    "source",
                    source["name"],
                    symbol.path,
                    source["line"],
                    files[symbol.path].sha256,
                    source["code"],
                )
                graph.link(sid, source_id, "observes-input-shaped-syntax")
                sources.append(source_id)
            for transform in symbol.transformations:
                tid = graph.add(
                    "transformation",
                    "Assignment: " + transform["target"],
                    symbol.path,
                    transform["line"],
                    files[symbol.path].sha256,
                    transform["code"],
                )
                graph.link(sid, tid, "observes-transformation")
                for source_id in sources:
                    graph.link(source_id, tid, "possible-syntax-dependency-not-taint-proof")
            for call in symbol.calls:
                influenced_at_call = set(influenced)
                # A conservative may-dependency union: reassignments/branches are not kill proofs.
                for transform in symbol.transformations:
                    if transform["line"] <= call["line"] and influenced_at_call.intersection(
                        transform["inputs"]
                    ):
                        influenced_at_call.add(transform["target"])
                if call["category"]:
                    oid = graph.add(
                        "operation",
                        call["category"] + ": " + call["name"],
                        symbol.path,
                        call["line"],
                        files[symbol.path].sha256,
                        call["code"],
                    )
                    graph.link(sid, oid, "contains-sensitive-call")
                    if influenced_at_call.intersection(call["identifiers"]):
                        for source_id in sources:
                            graph.link(
                                source_id, oid, "possible-argument-dependency-not-reachability"
                            )
                    evidence = list(dict.fromkeys([*chain, *sources, *control_ids, oid]))
                    paths.append(
                        {
                            "endpoint": endpoint,
                            "symbol": symbol,
                            "call": call,
                            "controls": controls,
                            "chain": [*chain, oid],
                            "evidence": evidence,
                            "input_dependency": bool(
                                influenced_at_call.intersection(call["identifiers"])
                            ),
                        }
                    )
                target = resolve_call(symbol, call, files, by_name)
                if target:
                    tid = symbol_ids[(target.path, target.line, target.name, target.owner)]
                    graph.link(sid, tid, "unique-syntactic-call-target")
                    arguments = call.get("argument_identifiers", [])
                    bound = {
                        parameter
                        for parameter, argument in zip(target.parameters, arguments, strict=False)
                        if influenced_at_call.intersection(argument)
                    }
                    visit(target, [*chain, tid], controls, (*stack, sid), depth + 1, bound)
                elif not call["category"]:
                    gap = graph.add(
                        "gap",
                        "Unresolved call: " + call["name"],
                        symbol.path,
                        call["line"],
                        files[symbol.path].sha256,
                        call["code"],
                    )
                    graph.link(sid, gap, "unresolved-call-binding")

        visit(
            endpoint,
            [symbol_ids[(endpoint.path, endpoint.line, endpoint.name, endpoint.owner)]],
            [],
            (),
            0,
            set(endpoint.parameters),
        )
    groups = {}
    for path in paths:
        key = (path["endpoint"].framework, path["call"]["name"].lower())
        groups.setdefault(key, []).append(path)
    hypotheses = []
    for path in paths:
        checkpoint(cancel, deadline)
        endpoint, symbol, call, controls = (
            path[k] for k in ("endpoint", "symbol", "call", "controls")
        )
        own_policy = any(
            c["kind"] in {"authorization-policy", "object-policy", "authorization-candidate"}
            for c in controls
        )
        peers = groups[(endpoint.framework, call["name"].lower())]
        stronger = [
            p
            for p in peers
            if p["endpoint"] != endpoint
            and any(c["kind"] in {"authorization-policy", "object-policy"} for c in p["controls"])
        ]
        rule, missing, title = "", [], ""
        extra_evidence = []
        if stronger and not own_policy:
            rule = "access-policy-inconsistency"
            missing = ["Authorization policy equivalent to related endpoint is not visible"]
            title = "Related sensitive operations have different visible access policies"
            extra_evidence = [e for p in stronger[:4] for e in p["evidence"]]
        # Object access signal requires an identifier-bearing singular resource operation.
        resource = call["category"] == "database" and re.search(
            r"(?:findUnique|findFirst|findById|getReferenceById|Find(?:Async)?|FirstOrDefault(?:Async)?|SingleOrDefaultAsync|update|deleteById)$",
            call["name"],
            re.I,
        )
        identifiers = set(call["identifiers"])
        for transform in reversed(symbol.transformations):
            if transform["line"] <= call["line"] and transform["target"] in identifiers:
                identifiers.update(transform["inputs"])
        has_id = any(re.search(r"(?:^id$|Id$|_id$)", name) for name in identifiers)
        object_candidate = any(
            c["kind"] == "object-policy"
            or c["kind"] == "object-filter-candidate"
            and c.get("path") == symbol.path
            and c.get("call_offset") == call.get("offset")
            for c in controls
        )
        if not rule and resource and has_id and path["input_dependency"] and not object_candidate:
            rule = "resource-authorization-context"
            missing = [
                "Resource ownership or object access control is not demonstrated on this path"
            ]
            title = "Identifier-bearing resource access needs object authorization review"
        if not rule:
            continue
        limitations = [
            *LIMITATIONS,
            *[item for file in files.values() for item in file.limitations],
        ]
        if ambient:
            limitations.append(
                "External security configuration candidates were found; applicability unresolved"
            )
        hypothesis_id = graph.add(
            "hypothesis",
            rule + ": " + endpoint.endpoint + ": " + call["name"],
            endpoint.path,
            endpoint.line,
            files[endpoint.path].sha256,
        )
        evidence = list(dict.fromkeys([*path["evidence"], *extra_evidence]))
        for eid in evidence:
            graph.link(eid, hypothesis_id, "supports-review-question")
        for control in ambient:
            cid = graph.add(
                "control",
                control["name"],
                control["path"],
                control["line"],
                files[control["path"]].sha256,
                control["code"],
            )
            graph.link(cid, hypothesis_id, "possible-counterevidence")
            evidence.append(cid)
        hypotheses.append(
            Hypothesis(
                rule=rule,
                title=title,
                operation=call["name"],
                path=endpoint.path,
                line=endpoint.line,
                endpoint=endpoint.endpoint,
                inputs=endpoint.sources,
                execution_path=path["chain"],
                controls=[*controls, *ambient],
                missing_controls=missing,
                limitations=list(dict.fromkeys(limitations)),
                confirmation=CONFIRMATION,
                evidence_ids=list(dict.fromkeys([*evidence, hypothesis_id])),
                confidence=0.65 if rule == "access-policy-inconsistency" and not ambient else 0.45,
            )
        )
    return {
        "graph": graph.build().model_dump(),
        "hypotheses": [h.model_dump() for h in hypotheses],
        "paths": len(paths),
        "symbols": len(symbols),
        "endpoints": sum(bool(s.endpoint) for s in symbols),
        "limitations": LIMITATIONS,
    }


def hypothesis_key(hypothesis: dict) -> str:
    return "|".join(hypothesis[k] for k in ("rule", "path", "endpoint", "operation"))


def compare_runs(
    previous: dict, current: dict, old_manifest: dict, manifest: dict, gaps=frozenset()
) -> list[dict]:
    old = {hypothesis_key(h): h for h in previous.get("hypotheses", [])}
    new = {hypothesis_key(h): h for h in current.get("hypotheses", [])}
    changes = []
    for key in sorted(old.keys() | new.keys()):
        item = new.get(key, old.get(key))
        graph = previous.get("graph", {}) if key not in new else current.get("graph", {})
        evidence_ids = set(item.get("evidence_ids", []))
        referenced_paths = {
            n["path"] for n in graph.get("nodes", []) if n["id"] in evidence_ids and n["path"]
        }
        changed = any(
            old_manifest.get(path) != manifest.get(path)
            for path in referenced_paths | {item["path"]}
        )
        state = (
            "previously-observed"
            if key in old and key in new
            else "unobserved-coverage-gap"
            if key not in new and (referenced_paths | {item["path"]}) & set(gaps)
            else "new-warning-in-changed-file"
            if key in new and changed
            else "new-review-signal"
            if key in new
            else "no-longer-observed"
        )
        changes.append(
            {
                "key": key,
                "state": state,
                "path": item["path"],
                "changed": changed,
                "interpretation": "Local observation history only; absence does not prove a fix, and first observation does not prove novelty",
            }
        )
    return changes


def run_research(
    engine, project: dict, scan_id: int, manifest: dict, cancel: Event, progress
) -> int:
    db = engine.db
    started = time.monotonic()
    deadline = started + engine.limits.timeout
    limits = ResearchLimits.model_validate(db.setting("research_limits", {}))
    metadata = json.loads(project["metadata"])
    root = engine.managed_snapshot(project["root"])
    previous = db.query(
        "SELECT manifest,data FROM research_runs WHERE project_id=? AND status='completed' ORDER BY id DESC LIMIT 1",
        (project["id"],),
    )
    from oberhau.maintenance import reserve

    storage_budget = reserve(db, history=len(json.dumps(manifest).encode()), project=project["id"])
    run_id = db.execute(
        "INSERT INTO research_runs(project_id,scan_id,status,started,commit_hash,manifest) VALUES(?,?,'running',?,?,?)",
        (project["id"], scan_id, now(), metadata.get("commit"), json.dumps(manifest)),
    )
    scanner_id = db.execute(
        "INSERT INTO scanner_runs(scan_id,scanner,status,started) VALUES(?,'contextual','running',?)",
        (scan_id, now()),
    )
    parsed, reused, size = 0, 0, 0
    gaps: dict[str, str] = {}
    sessions: list[ParserSession] = []

    def parser() -> ParserSession:
        # A per-file failure closes its worker; the following files get a fresh one.
        if not sessions or sessions[-1].closed:
            sessions.append(
                ParserSession(
                    cancel, deadline, limits.parser_timeout_seconds, limits.parser_memory_mib
                )
            )
        return sessions[-1]

    def verify_parser() -> None:
        # A gap is per-file only while a fresh worker still completes a trivial control file;
        # otherwise a broken parser environment would pass as a clean, incomplete run.
        try:
            parser().parse(PARSER_CONTROL, hashlib.sha256(b"").hexdigest(), b"")
        except ParserFileError:
            raise OberhauError(
                "Isolated parser could not complete its built-in control file"
            ) from None

    verified = False
    try:
        files = {}
        for path, digest in manifest.items():
            checkpoint(cancel, deadline)
            if PurePosixPath(path).suffix not in EXTENSIONS:
                continue
            with confined(root, path).open("rb") as stream:
                content = stream.read(engine.limits.max_file_bytes + 1)
            if (
                len(content) > engine.limits.max_file_bytes
                or hashlib.sha256(content).hexdigest() != digest
            ):
                raise OberhauError("Research source integrity failed: " + path)
            cached = db.query(
                "SELECT data FROM research_files WHERE project_id=? AND path=? AND sha256=? AND version=?",
                (project["id"], path, digest, PARSER_VERSION),
            )
            if cached:
                summary = FileSummary.model_validate_json(cached[0]["data"])
                reused += 1
            else:
                progress("Contextual indexing: " + path)
                try:
                    summary = parser().parse(path, digest, content)
                except ParserFileError as error:
                    # Cancellation and the run deadline are never a per-file coverage gap.
                    checkpoint(cancel, deadline)
                    gaps[path] = str(error)
                    if not verified:
                        verify_parser()
                        verified = True
                    continue
                verified = True
                # Cache contains redacted observations, no executable trees or raw source.
                summary = FileSummary.model_validate(sanitize(summary.model_dump()))
                parsed += 1
                reserve(db, cache=len(summary.model_dump_json().encode()), current=storage_budget)
                db.execute(
                    "INSERT OR REPLACE INTO research_files VALUES(?,?,?,?,?)",
                    (project["id"], path, digest, PARSER_VERSION, summary.model_dump_json()),
                )
            size += len(summary.model_dump_json().encode("utf-8"))
            if size > limits.max_index_bytes:
                raise OberhauError("Research serialized index budget exceeded")
            files[path] = summary
        parser_memory = combined_memory(sessions)
        for session in sessions:
            session.close()
        result = analyze(
            files, limits, cancel, deadline, str(project["id"]), metadata.get("commit", "")
        )
        if gaps:
            # Excluded files may hold the controls or call targets these hypotheses lack.
            gap_note = (
                f"Parser coverage gaps: {len(gaps)} file(s) excluded; their controls, "
                "exports and call targets are unobserved"
            )
            result["limitations"] = [*result["limitations"], gap_note]
            for hypothesis in result["hypotheses"]:
                hypothesis["limitations"].append(gap_note)
        result["index"] = {
            "parsed": parsed,
            "reused": reused,
            "parser_gaps": len(gaps),
            "bytes": size,
            "version": PARSER_VERSION,
            "parser_isolation": "separate process; bounded JSON; no imported-code execution",
            "parser_timeout_seconds": limits.parser_timeout_seconds,
            "parser_memory": parser_memory,
        }
        result["coverage"] = {
            path: {"parser": files[path].parser, "limitations": files[path].limitations}
            if path in files
            else {
                "parser": "unavailable",
                "limitations": [
                    f"Parser coverage gap: {gaps[path]}; file excluded from contextual paths"
                ],
            }
            for path in manifest
            if path in files or path in gaps
        }
        result["snapshot"] = root.relative_to(engine.home).as_posix()
        previous_data = json.loads(previous[0]["data"]) if previous else {}
        previous_manifest = json.loads(previous[0]["manifest"]) if previous else {}
        result["changes"] = compare_runs(
            previous_data,
            result,
            previous_manifest,
            manifest,
            gaps,
        )
        from oberhau.git_intelligence import changes

        result["git_intelligence"] = changes(
            previous_data, result, previous_manifest, manifest, gaps
        )
        history = db.query(
            "SELECT data FROM research_runs WHERE project_id=? AND status='completed' ORDER BY id DESC LIMIT 20",
            (project["id"],),
        )
        historical_keys = {
            hypothesis_key(h)
            for row in history
            for h in json.loads(row["data"]).get("hypotheses", [])
        }
        for change in result["changes"]:
            if (
                change["state"] in {"new-warning-in-changed-file", "new-review-signal"}
                and change["key"] in historical_keys
            ):
                change["state"] = "possible-regression"
        nodes = {n["id"]: n for n in result["graph"]["nodes"]}
        # Location relationships preserve scanner evidence without inventing equivalence.
        graph = GraphBuilder(limits.max_nodes)
        from oberhau.research_models import EvidenceEdge, EvidenceNode

        graph.nodes = {n["id"]: EvidenceNode.model_validate(n) for n in result["graph"]["nodes"]}
        graph.edges = {
            (e["source"], e["target"], e["relation"]): EvidenceEdge.model_validate(e)
            for e in result["graph"]["edges"]
        }
        for row in db.query(
            "SELECT o.finding_id,o.data FROM observations o WHERE o.scan_id=?", (scan_id,)
        ):
            observation = Finding.model_validate_json(row["data"])
            aid = graph.add(
                "scanner",
                f"{observation.scanner}:{observation.rule}:finding-{row['finding_id']}",
                observation.path,
                observation.line,
                observation.evidence.get("source_sha256") or "",
                observation.context,
            )
            for node in list(graph.nodes.values()):
                if node.path == observation.path and node.kind in {"endpoint", "function"}:
                    graph.link(aid, node.id, "same-file-review-reference-only")
        result["graph"] = graph.build().model_dump()
        # Publish findings and graph atomically. Cancellation leaves cached files but no partial hypotheses.
        checkpoint(cancel, deadline)
        findings = []
        for hypothesis in result["hypotheses"]:
            references = [
                {"path": nodes[e]["path"], "line": nodes[e]["line"], "sha256": nodes[e]["sha256"]}
                for e in hypothesis["evidence_ids"]
                if nodes[e]["path"] and nodes[e]["sha256"]
            ]
            finding = Finding(
                scanner="contextual",
                rule=hypothesis["rule"],
                category="authorization",
                title=hypothesis["title"],
                path=hypothesis["path"],
                line=hypothesis["line"],
                end_line=hypothesis["line"],
                confidence=hypothesis["confidence"],
                severity=hypothesis["severity"],
                explanation="Research hypothesis: " + "; ".join(hypothesis["missing_controls"]),
                status=Status.SUSPECTED,
                evidence={
                    "snapshot": str(root),
                    "source_sha256": manifest[hypothesis["path"]],
                    "scan": scan_id,
                    "research_run": run_id,
                    "hypothesis": hypothesis,
                    "references": references,
                    "source_recently_changed": any(
                        previous_manifest.get(ref["path"]) != manifest.get(ref["path"])
                        for ref in references
                    )
                    if previous
                    else False,
                },
            )
            findings.append(finding)
        result = sanitize(result)
        reserve(db, history=len(json.dumps(result).encode()), current=storage_budget)
        with db.connect() as connection:
            for finding in findings:
                checkpoint(cancel, deadline)
                db.save_finding(project["id"], scan_id, finding, connection)
            connection.execute(
                "UPDATE research_runs SET status='completed',finished=?,data=?,duration=? WHERE id=?",
                (now(), json.dumps(result), time.monotonic() - started, run_id),
            )
            connection.execute(
                "UPDATE scanner_runs SET status='completed',finished=?,duration=?,findings=?,provenance=? WHERE id=?",
                (
                    now(),
                    time.monotonic() - started,
                    len(findings),
                    json.dumps(
                        {
                            "version": PARSER_VERSION,
                            "offline": True,
                            "limits": limits.model_dump(),
                            "parser_gaps": sorted(gaps),
                        }
                    ),
                    scanner_id,
                ),
            )
        progress(
            f"Contextual research #{run_id}: {len(findings)} hypotheses; {parsed} parsed, {reused} cached"
            + (f", {len(gaps)} parser coverage gaps" if gaps else "")
        )
        return run_id
    except BaseException as error:
        status = "cancelled" if isinstance(error, Cancelled) else "failed"
        errors = json.dumps(sanitize([str(error) or type(error).__name__]))
        db.execute(
            "UPDATE research_runs SET status=?,finished=?,duration=?,errors=? WHERE id=?",
            (status, now(), time.monotonic() - started, errors, run_id),
        )
        db.execute(
            "UPDATE scanner_runs SET status=?,finished=?,errors=? WHERE id=?",
            (status, now(), errors, scanner_id),
        )
        raise
    finally:
        for session in sessions:
            session.close()


def combined_memory(sessions: list[ParserSession]) -> dict:
    metrics = [session.memory_metrics() for session in sessions if session.process is not None]
    if not metrics:
        return {"enforced": False, "reason": "No Windows parser job was started"}
    combined = dict(metrics[-1])
    if "peak_committed_bytes" in combined:
        combined["peak_committed_bytes"] = max(
            (m["peak_committed_bytes"] for m in metrics if m.get("peak_committed_bytes")),
            default=None,
        )
    combined["workers"] = len(metrics)
    return combined


def research_queue(db, project_id: int | None = None) -> list[dict]:
    rows = db.query(
        "SELECT * FROM findings"
        + (" WHERE project_id=?" if project_id is not None else "")
        + " ORDER BY id",
        (project_id,) if project_id is not None else (),
    )
    queue = []
    for row in rows:
        finding = Finding.model_validate_json(row["data"])
        evidence = finding.evidence
        hypothesis = evidence.get("hypothesis", {})
        controls = hypothesis.get("controls", [])
        validations = db.query("SELECT result FROM validations WHERE finding_id=?", (row["id"],))
        reproduced = any(json.loads(v["result"]).get("passed") for v in validations)
        quality = (
            "referenced-path"
            if hypothesis.get("evidence_ids")
            else "scanner-location"
            if evidence.get("source_sha256")
            else "limited"
        )
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informative": 0}.get(
            finding.severity, 2
        )
        priority = (
            severity_rank * 10
            + round(finding.confidence * 10)
            + (10 if reproduced else 0)
            + (4 if quality == "referenced-path" else 0)
        )
        if row["status"] in {Status.FALSE_POSITIVE, Status.FIXED, Status.NA, Status.DUPLICATE}:
            priority -= 100
        if any(
            c.get("kind") in {"external-policy-candidate", "middleware-candidate"} for c in controls
        ):
            priority -= 3
        if evidence.get("source_recently_changed"):
            priority += 2
        queue.append(
            {
                "id": row["id"],
                "project": row["project_id"],
                "title": finding.title,
                "status": row["status"],
                "priority": priority,
                "severity_estimate": finding.severity,
                "detection_confidence": finding.confidence,
                "evidence_quality": quality,
                "local_reproduction": reproduced,
                "possible_impact": "unverified",
                "control_coverage": controls,
                "known_advisories": finding.advisories,
                "eligibility": "unknown; human policy review required",
                "history": {"occurrences": row["occurrences"], "human_notes": row["notes"]},
                "duplicate_status": "human-marked"
                if row["status"] == Status.DUPLICATE
                else "not established",
                "reasons": [
                    f"Severity estimate {finding.severity}; confidence {finding.confidence:.0%}",
                    f"Evidence {quality}; local reproduction {reproduced}",
                    "Human decisions lower priority and retain the record"
                    if priority < 0
                    else "Control applicability and program eligibility still require review",
                ],
            }
        )
    return sorted(queue, key=lambda item: (-item["priority"], item["id"]))
