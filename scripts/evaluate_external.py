"""Score fixed external labels, then inspect a real application without executing it."""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from threading import Event

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from oberhau.core import Limits  # noqa: E402
from oberhau.engine import Engine  # noqa: E402
from oberhau.framework_analysis import EXTENSIONS  # noqa: E402
from oberhau.parser_isolation import ParserSession  # noqa: E402
from oberhau.research import analyze  # noqa: E402
from oberhau.research_models import ResearchLimits  # noqa: E402
from oberhau.scanners.builtin import BuiltinScanner, call_name  # noqa: E402

DIRECTORY = ROOT / ".oberhau/external-evaluation"
LABELS = ROOT / "evaluation/external-labels.json"


def freeze_labels():
    """Upstream comments define SQL controls; explicit shell syntax defines boundaries.

    This happens BEFORE any detector runs. Never tune these labels to observed output.
    """
    import ast

    labels = []
    path = "examples/sql_statements.py"
    text = (DIRECTORY / "bandit" / path).read_text()
    lines = text.splitlines()
    states, state = {}, None
    for i, line in enumerate(lines, 1):
        if line.startswith("# bad"):
            state = True
        elif line.startswith("# good") or line.startswith("# real world false positives"):
            state = False
        elif line.startswith("# bug:"):
            state = None
        states[i] = state
    for node in ast.parse(text).body:
        if states.get(node.lineno) is None or not isinstance(node, (ast.Assign, ast.Expr)):
            continue
        labels.append(
            {
                "project": "bandit",
                "path": path,
                "line": node.lineno,
                "positive": states[node.lineno],
                "rule": "python-sql-format",
                "scope": "SQL execution"
                if isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and call_name(node.value.func).endswith(".execute")
                else "SQL construction / false-positive control",
                "basis": "Upstream #bad, #good and #real world false positives sections",
            }
        )
    path = "examples/subprocess_shell.py"
    for node in ast.walk(ast.parse((DIRECTORY / "bandit" / path).read_text())):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node.func)
        if not (name.startswith("subprocess.") or name in {"pop", "Popen"}):
            continue
        shell = next((k.value for k in node.keywords if k.arg == "shell"), None)
        if shell is not None and not (
            isinstance(shell, ast.Constant) and shell.value in (True, False, None, 0, 1)
        ):
            continue  # Nonliteral/truthy string/collection cases have no boolean label here.
        positive = name != "Popen" and (
            name in {"subprocess.getoutput", "subprocess.getstatusoutput"}
            or isinstance(shell, ast.Constant)
            and bool(shell.value)
        )
        labels.append(
            {
                "project": "bandit",
                "path": path,
                "line": node.lineno,
                "positive": bool(positive),
                "rule": "python-shell",
                "scope": "Shell syntax boundary",
                "basis": "Upstream subprocess fixture; explicit true/false/absent shell, unconditional shell helpers; local Popen is a negative control",
            }
        )
    labels.append(
        {
            "project": "bandit",
            "path": "examples/exec.py",
            "line": 1,
            "positive": True,
            "rule": "python-dynamic-code",
            "scope": "Dynamic execution boundary",
            "basis": "Upstream exec fixture",
        }
    )
    for filename, method, positive in [
        ("idor/IDORViewOtherProfile.java", "completed", True),
        ("idor/IDOREditOtherProfile.java", "completed", True),
        ("missingac/MissingFunctionACUsers.java", "usersService", True),
        ("missingac/MissingFunctionACUsers.java", "usersFixed", False),
    ]:
        labels.append(
            {
                "project": "webgoat",
                "path": "src/main/java/org/owasp/webgoat/lessons/" + filename,
                "method": method,
                "positive": positive,
                "scope": "Authorization lesson",
                "basis": "Upstream deliberately vulnerable lesson and explicitly named admin-fix control; custom session/domain logic exceeds current detector patterns",
            }
        )
    LABELS.write_text(
        json.dumps(
            {
                "method": "Frozen before initial evaluation. Upstream-authored sources and comments; mapping to Oberhau categories by this release reviewer, not a blind third-party audit. Risky syntax is a review signal, not exploit proof.",
                "cases": labels,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Frozen {len(labels)} external labels; no detector executed")


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--freeze-labels", action="store_true")
    options = args.parse_args()
    if options.freeze_labels:
        if LABELS.exists():
            raise RuntimeError(
                "Labels already frozen; review a new dataset explicitly instead of overwriting"
            )
        freeze_labels()
        return
    started = time.monotonic()
    manifest = json.loads((ROOT / "evaluation/external-sources.json").read_text())
    for file in manifest["files"]:
        if (
            hashlib.sha256((DIRECTORY / file["project"] / file["path"]).read_bytes()).hexdigest()
            != file["sha256"]
        ):
            raise RuntimeError("External source integrity failed")
    dataset = json.loads(LABELS.read_text())
    cancel = Event()
    detections = BuiltinScanner().scan(
        DIRECTORY / "bandit",
        ["examples/sql_statements.py", "examples/subprocess_shell.py", "examples/exec.py"],
        cancel,
        Limits(),
        lambda _: None,
        ["unsafe-code"],
    )
    predicted = {(f.path, f.line, f.rule) for f in detections}
    summaries = {}
    with ParserSession(cancel, time.monotonic() + 120) as parser:
        for file in manifest["files"]:
            if file["project"] != "webgoat" or Path(file["path"]).suffix not in EXTENSIONS:
                continue
            code = (DIRECTORY / "webgoat" / file["path"]).read_bytes()
            summaries[file["path"]] = parser.parse(file["path"], file["sha256"], code)
        contextual = analyze(summaries, ResearchLimits(), cancel, time.monotonic() + 120)
    results = []
    for case in dataset["cases"]:
        if case["project"] == "bandit":
            detected = (case["path"], case["line"], case["rule"]) in predicted
        else:
            symbols = [s for s in summaries[case["path"]].symbols if s.name == case["method"]]
            detected = any(
                h["path"] == case["path"] and any(h["line"] == s.line for s in symbols)
                for h in contextual["hypotheses"]
            )
        label = (
            "TP"
            if case["positive"] and detected
            else "FN"
            if case["positive"]
            else "FP"
            if detected
            else "TN"
        )
        results.append({**case, "detected": detected, "result": label})
    known = {
        (c["path"], c.get("line"), c.get("rule"))
        for c in dataset["cases"]
        if c["project"] == "bandit"
    }

    def metrics(cases):
        counts = {key: sum(c["result"] == key for c in cases) for key in ("TP", "FP", "TN", "FN")}
        return {
            **counts,
            "precision": counts["TP"] / (counts["TP"] + counts["FP"])
            if counts["TP"] + counts["FP"]
            else None,
            "recall": counts["TP"] / (counts["TP"] + counts["FN"])
            if counts["TP"] + counts["FN"]
            else None,
        }

    # Real application, deliberately unlabelled: do not treat its alerts as proven bugs or FP.
    engine = Engine(ROOT / ".oberhau/external-application-results")
    project = engine.ingestion.add(
        DIRECTORY / "prisma/orm/nextjs", "EXTERNAL EVALUATION / Prisma Next.js"
    )
    scan = engine.scan(project, "research")
    run = engine.db.query(
        "SELECT * FROM research_runs WHERE project_id=? ORDER BY id DESC LIMIT 1", (project,)
    )[0]
    application = json.loads(run["data"])
    report = {
        "seconds": time.monotonic() - started,
        "sources_sha256": hashlib.sha256(
            (ROOT / "evaluation/external-sources.json").read_bytes()
        ).hexdigest(),
        "labels_sha256": hashlib.sha256(LABELS.read_bytes()).hexdigest(),
        "metrics": metrics(results),
        "by_scope": {
            scope: metrics([c for c in results if c["scope"] == scope])
            for scope in sorted({c["scope"] for c in results})
        },
        "cases": results,
        "unlabelled_predictions": [
            {"path": p, "line": line, "rule": rule} for p, line, rule in sorted(predicted - known)
        ],
        "application": {
            "project": project,
            "scan": scan,
            "status": run["status"],
            "files": len(json.loads(run["manifest"])),
            "symbols": application.get("symbols"),
            "endpoints": application.get("endpoints"),
            "hypotheses": application.get("hypotheses"),
            "index": application.get("index"),
        },
        "limitations": [
            dataset["method"],
            "Selected upstream cases, not full Bandit or WebGoat scorecards, not representative field precision",
            "SQL construction without execution and custom WebGoat domain/session access logic exceed current pattern coverage; misses are retained",
            "Prisma application has no independent vulnerability labels; alerts are unverified and excluded from confusion metrics",
            "Downloaded projects are data only: no package installation, dependency loading, server startup or external target testing",
        ],
    }
    target = ROOT / "artifacts/oberhau-1.0-external-evaluation.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "report": str(target),
                "metrics": report["metrics"],
                "by_scope": report["by_scope"],
                "application": {
                    k: v for k, v in report["application"].items() if k != "hypotheses"
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
