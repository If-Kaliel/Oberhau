"""Independent static detection evaluation, never execute fixture source."""

from __future__ import annotations

import hashlib
import json
import time
import tracemalloc
from pathlib import Path
from threading import Event, Lock

from oberhau.framework_analysis import checkpoint, parse_file
from oberhau.research import analyze
from oberhau.research_models import ResearchLimits
from oberhau.resources import process_memory

BENCHMARK_LOCK = Lock()
DATASET = Path(__file__).parent / "assets/research_benchmark.json"


def evaluate(cancel: Event | None = None) -> dict:
    from oberhau.core import OberhauError

    cancel = cancel or Event()
    if not BENCHMARK_LOCK.acquire(blocking=False):
        raise OberhauError("A benchmark is already running")
    tracing = tracemalloc.is_tracing()
    try:
        raw = DATASET.read_bytes()
        dataset = json.loads(raw)
        results = []
        started = time.monotonic()
        deadline = started + 60
        if not tracing:
            tracemalloc.start()
        for case in dataset["cases"]:
            checkpoint(cancel, deadline)
            begin = time.monotonic()
            summaries = {}
            for path, text in case["sources"].items():
                code = text.encode()
                summaries[path] = parse_file(
                    path, hashlib.sha256(code).hexdigest(), code, cancel, deadline
                )
            found = analyze(summaries, ResearchLimits(), cancel, deadline)
            # Count individual signals, including duplicate-rule predictions as extra positives.
            expected = list(case["expected"])
            remaining = list(expected)
            detected = [h["rule"] for h in found["hypotheses"]]
            true, false = 0, 0
            for rule in detected:
                if rule in remaining:
                    remaining.remove(rule)
                    true += 1
                else:
                    false += 1
            results.append(
                {
                    "id": case["id"],
                    "framework": case["framework"],
                    "expected": expected,
                    "detected": detected,
                    "missed": remaining,
                    "true_positives": true,
                    "false_positives": false,
                    "false_negatives": len(remaining),
                    "seconds": time.monotonic() - begin,
                }
            )
        _, peak = tracemalloc.get_traced_memory()
        tp = sum(r["true_positives"] for r in results)
        fp = sum(r["false_positives"] for r in results)
        fn = sum(r["false_negatives"] for r in results)
        return {
            "dataset": dataset["name"],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "cases": results,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "seconds": time.monotonic() - started,
            "peak_python_bytes": peak,
            "process_memory": process_memory(),
            "memory_limitations": "tracemalloc observes Python allocations; native Tree-sitter allocations, RSS and GPU memory are not measured. A pre-existing tracer includes prior/concurrent activity.",
            "categories": sorted({rule for case in dataset["cases"] for rule in case["expected"]}),
            "limitations": dataset["limitations"],
        }
    finally:
        if not tracing and tracemalloc.is_tracing():
            tracemalloc.stop()
        BENCHMARK_LOCK.release()
