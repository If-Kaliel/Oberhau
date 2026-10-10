"""Bounded same-file Python assignment slices and direct callers, never runtime execution."""

from __future__ import annotations

import ast

from oberhau.security import redact_source


def name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name_of(node.value) + "." + node.attr
    return ""


def source_trace(text: str, line: int, rule: str) -> dict:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return {"available": False, "reason": "Python syntax could not be parsed"}
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= node.end_lineno
    ]
    function = min(functions, key=lambda node: node.end_lineno - node.lineno) if functions else None
    scope = function or tree
    safe_lines = redact_source(text).splitlines()
    aliases = {}
    imports = [*tree.body, *(function.body if function else [])]
    for node in imports:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def resolved(node):
        value = name_of(node)
        head, _, tail = value.partition(".")
        if head in shadowed and head in aliases:
            return "<local>." + value
        replacement = aliases.get(head, head) if head not in shadowed else head
        return replacement + ("." + tail if tail else "")

    nodes = []
    parents = {}

    def walk(node):
        nodes.append(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            parents[child] = node
            walk(child)

    try:
        walk(scope)
    except RecursionError:
        return {"available": False, "reason": "Python structure exceeds local slice depth"}
    calls = [
        node for node in nodes if isinstance(node, ast.Call) and node.lineno == line and node.args
    ]
    suffix = rule.split(".")[-1]
    if "sql" in suffix:
        calls = [
            node for node in calls if name_of(node.func).endswith((".execute", ".executemany"))
        ]
    elif "eval" in suffix or "dynamic-code" in suffix:
        calls = [node for node in calls if name_of(node.func) in {"eval", "exec"}]
    if not calls:
        return {"available": False, "reason": "No matching argument-bearing call at recorded line"}
    sink = calls[0]
    parameters = (
        {
            arg.arg
            for arg in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
        }
        if function
        else set()
    )
    assignments = {}
    shadowed = set(parameters)
    if function:
        shadowed.update(
            node.id
            for node in nodes
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        )
    for node in nodes:
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, (ast.AnnAssign, ast.NamedExpr))
            else []
        )
        value = getattr(node, "value", None)
        for target in targets:
            if isinstance(target, ast.Name) and value is not None:
                assignments.setdefault(target.id, []).append((node.lineno, value))
    sources, steps, unknown = {}, {}, set()
    gaps, sanitizers = [], []
    truncated, visited = False, 0

    def excerpt(number):
        return safe_lines[number - 1].strip()[:500] if 0 < number <= len(safe_lines) else ""

    def add_source(kind, number, expression):
        sources[(kind, number, expression)] = {
            "kind": kind,
            "line": number,
            "expression": expression,
            "code": excerpt(number),
        }

    def trace(node, before, stack=()):
        nonlocal truncated, visited
        visited += 1
        if visited > 256 or len(stack) > 16:
            truncated = True
            return
        if isinstance(node, ast.Name):
            candidates = [
                item
                for item in assignments.get(node.id, [])
                if item[0] <= before and (node.id, item[0]) not in stack
            ]
            if candidates:

                def conditional(value):
                    current = parents.get(value)
                    while current is not None and current is not scope:
                        if isinstance(
                            current,
                            (
                                ast.If,
                                ast.For,
                                ast.AsyncFor,
                                ast.While,
                                ast.Try,
                                ast.TryStar,
                                ast.Match,
                            ),
                        ):
                            return True
                        current = parents.get(current)
                    return False

                straight = [item for item in candidates if not conditional(item[1])]
                baseline = max(straight, key=lambda item: item[0]) if straight else None
                selected = ([baseline] if baseline else []) + [
                    item
                    for item in candidates
                    if conditional(item[1]) and (baseline is None or item[0] >= baseline[0])
                ]
                if any(conditional(value) for _, value in selected):
                    gaps.append(
                        {
                            "variable": node.id,
                            "reason": "Conditional/loop assignments have multiple possible reaching definitions; feasibility unresolved",
                        }
                    )
                    if baseline is None and node.id in parameters:
                        add_source(
                            "function parameter; caller trust unknown", function.lineno, node.id
                        )
                for number, value in selected:
                    steps[(number, node.id)] = {
                        "line": number,
                        "variable": node.id,
                        "code": excerpt(number),
                    }
                    trace(value, number, (*stack, (node.id, number)))
            elif node.id in parameters:
                add_source("function parameter; caller trust unknown", function.lineno, node.id)
            elif node.id not in {"True", "False", "None"}:
                unknown.add(node.id)
            return
        if isinstance(node, ast.Call):
            callee = resolved(node.func)
            if callee in {"html.escape", "shlex.quote", "bleach.clean"}:
                sanitizers.append(
                    {
                        "line": node.lineno,
                        "operation": callee,
                        "code": excerpt(node.lineno),
                        "limitations": "Syntactic sanitizer call; runtime binding, configuration and sink applicability unverified",
                    }
                )
            if callee == "input" and "input" not in shadowed:
                add_source("interactive input", node.lineno, callee)
                return
            if callee.startswith(
                (
                    "flask.request.args.",
                    "flask.request.form.",
                    "flask.request.values.",
                    "flask.request.get_json",
                )
            ):
                add_source("Flask request input", node.lineno, callee)
                return
            if isinstance(node.func, ast.Attribute):
                trace(node.func.value, before, stack)
            for child in [*node.args, *(keyword.value for keyword in node.keywords)]:
                trace(child, before, stack)
            return
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            value = name_of(node.value if isinstance(node, ast.Subscript) else node)
            if resolved(node.value if isinstance(node, ast.Subscript) else node).startswith(
                ("flask.request.args", "flask.request.form", "flask.request.json")
            ):
                add_source("Flask request input", node.lineno, value)
                return
            if value.startswith(
                ("request.GET", "request.POST", "request.query_params", "request.data")
            ):
                add_source(
                    "HTTP-shaped request access; framework identity unresolved", node.lineno, value
                )
                return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                trace(child, before, stack)

    for argument in sink.args:
        trace(argument, sink.lineno)
    callers = []
    top_level = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if function and function in tree.body and function.name in top_level:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == function.name
            ):
                callers.append({"line": node.lineno, "code": excerpt(node.lineno)})
    return {
        "available": True,
        "function": function.name if function else "<module>",
        "parameters": sorted(parameters),
        "sink": {
            "line": sink.lineno,
            "operation": resolved(sink.func),
            "code": excerpt(sink.lineno),
        },
        "sources": list(sources.values())[:16],
        "assignments": sorted(steps.values(), key=lambda step: step["line"])[:32],
        "unresolved_names": sorted(unknown)[:16],
        "same_name_call_sites": callers[:16],
        "truncated": truncated or len(sources) > 16 or len(steps) > 32 or len(callers) > 16,
        "analysis_gaps": gaps[:16],
        "sanitizers": sanitizers[:16],
        "conditional_checks": [
            {
                "line": node.lineno,
                "code": excerpt(node.lineno),
                "effect": "Condition observed; enforcement and path dominance unresolved",
            }
            for node in nodes
            if isinstance(node, ast.If)
        ][:16],
        "limitations": [
            "Static same-function may-dependency slice; straight-line definitions and subsequent conditional alternatives are retained",
            "Branch feasibility, dynamic dispatch, imports and interprocedural control flow are not resolved",
            "Same-name call sites are syntactic references; target bindings are not verified",
            "A parameter or request-shaped access does not prove attacker control or exploitability",
        ],
    }
