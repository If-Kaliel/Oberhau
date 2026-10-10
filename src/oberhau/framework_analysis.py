"""Bounded syntax indexing with language-specific parsers and framework profiles.

Calls and controls are observations, not runtime binding or dominance proofs.
"""

from __future__ import annotations

import ast
import re
import time
import warnings
from pathlib import PurePosixPath
from threading import Event

from oberhau.core import Cancelled, OberhauError
from oberhau.research_models import FileSummary, Symbol
from oberhau.security import redact_source

PARSER_VERSION = "contextual-1"
EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".java", ".cs", ".py"}
FUNCTIONS = {
    "function_declaration",
    "generator_function_declaration",
    "method_declaration",
    "arrow_function",
    "function_expression",
    "lambda_expression",
}
CALLS = {
    "call_expression",
    "method_invocation",
    "invocation_expression",
    "object_creation_expression",
}


def checkpoint(cancel: Event, deadline: float) -> None:
    if cancel.is_set():
        raise Cancelled()
    if time.monotonic() >= deadline:
        raise OberhauError("Contextual investigation deadline exceeded")


def walk(node, cancel: Event, deadline: float, skip_functions=False):
    stack = [node]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited % 128 == 0:
            checkpoint(cancel, deadline)
        yield current
        stack.extend(
            reversed(
                [c for c in current.named_children if not (skip_functions and c.type in FUNCTIONS)]
            )
        )
        if visited > 200000:
            raise OberhauError("File syntax node budget exceeded")


def classify_operation(name: str, framework: str) -> str:
    # Names are syntax-only; receiver/type bindings are explicitly unresolved.
    leaf = name.split(".")[-1]
    if framework == "next-node":
        if re.search(
            r"\.(?:findUnique|findFirst|findMany|update|delete|create|query|execute|select|insert|destroy)$",
            name,
        ):
            return "database"
        if leaf in {"exec", "execSync", "spawn", "spawnSync"}:
            return "process"
        if leaf in {"readFile", "writeFile", "readFileSync", "writeFileSync", "unlink"}:
            return "file"
        if leaf in {"fetch", "request"}:
            return "outbound-http"
        if leaf in {"render", "send"}:
            return "render"
    elif framework == "spring":
        if leaf in {
            "findById",
            "getReferenceById",
            "save",
            "deleteById",
            "findAll",
            "executeQuery",
            "executeUpdate",
        }:
            return "database"
        if leaf in {"exec", "start"} and "Runtime" in name or "ProcessBuilder" in name:
            return "process"
        if leaf in {"readAllBytes", "write", "delete"} and "Files" in name:
            return "file"
        if leaf in {"getForObject", "exchange", "send"}:
            return "outbound-http"
    elif framework == "aspnet":
        if leaf in {
            "Find",
            "FindAsync",
            "FirstOrDefault",
            "FirstOrDefaultAsync",
            "SingleOrDefaultAsync",
            "SaveChanges",
            "SaveChangesAsync",
            "ExecuteSqlRaw",
            "ExecuteSqlRawAsync",
            "Remove",
        }:
            return "database"
        if name.endswith("Process.Start"):
            return "process"
        if leaf in {"ReadAllText", "WriteAllText", "ReadAllBytes", "Delete"} and "File" in name:
            return "file"
        if leaf in {"GetAsync", "PostAsync", "SendAsync"}:
            return "outbound-http"
    elif framework == "python":
        if leaf in {"execute", "executemany"}:
            return "database"
        if name in {"eval", "exec"} or name.endswith(
            ("os.system", "subprocess.run", "subprocess.Popen")
        ):
            return "process"
        if name == "open":
            return "file"
    return ""


def parse_file(
    path: str, digest: str, content: bytes, cancel: Event, deadline: float
) -> FileSummary:
    checkpoint(cancel, deadline)
    if PurePosixPath(path).suffix == ".py":
        return parse_python(path, digest, content)
    import tree_sitter_c_sharp
    import tree_sitter_java
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language, Parser

    suffix = PurePosixPath(path).suffix
    capsule, framework = {
        ".ts": (tree_sitter_typescript.language_typescript, "next-node"),
        ".tsx": (tree_sitter_typescript.language_tsx, "next-node"),
        ".js": (tree_sitter_javascript.language, "next-node"),
        ".jsx": (tree_sitter_javascript.language, "next-node"),
        ".java": (tree_sitter_java.language, "spring"),
        ".cs": (tree_sitter_c_sharp.language, "aspnet"),
    }[suffix]
    parser = Parser(Language(capsule()))
    # The 0.25.2 Windows progress_callback path crashed during native verification.
    # Its supported timeout API avoids that native bug; cancellation resumes after parsing.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", message="Use the progress_callback in parse", category=DeprecationWarning
        )
        parser.timeout_micros = max(1, int((deadline - time.monotonic()) * 1_000_000))
    tree = parser.parse(content)
    if tree is None:
        checkpoint(cancel, deadline)
        raise OberhauError("Native parser exceeded the investigation deadline")
    checkpoint(cancel, deadline)
    result = FileSummary(path=path, sha256=digest, parser=f"tree-sitter:{framework}")
    safe_lines = redact_source(content.decode("utf-8", errors="replace")).splitlines()

    def text(node):
        return (
            content[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            if node
            else ""
        )

    def loc(node, **fields):
        line = node.start_point.row + 1
        return {"line": line, "code": safe_lines[line - 1][:500], **fields}

    def ancestors(node):
        values = []
        current = node.parent
        while current:
            values.append(current)
            current = current.parent
        return values

    def call_name(node):
        if node.type == "method_invocation":
            obj = text(node.child_by_field_name("object"))
            return (obj + "." if obj else "") + text(node.child_by_field_name("name"))
        if node.type == "object_creation_expression":
            return text(node.child_by_field_name("type"))
        return text(node.child_by_field_name("function"))

    def identifiers(node):
        return (
            sorted(
                {
                    text(n)
                    for n in walk(node, cancel, deadline)
                    if n.type
                    in {"identifier", "property_identifier", "shorthand_property_identifier"}
                }
            )[:64]
            if node
            else []
        )

    nodes = list(walk(tree.root_node, cancel, deadline))
    if tree.root_node.has_error:
        # Never manufacture complete paths through error-recovered syntax.
        result.limitations.append("Syntax errors: file excluded from contextual paths")
        return result
    for node in nodes:
        if node.type == "import_statement":
            source = text(node.child_by_field_name("source")).strip("\"'")
            for item in walk(node, cancel, deadline):
                if item.type == "import_specifier":
                    name = text(item.child_by_field_name("name"))
                    alias = text(item.child_by_field_name("alias")) or name
                    result.imports[alias] = {"module": source, "name": name}
        if node.type in CALLS:
            name = call_name(node)
            if name.endswith(
                (
                    "SecurityFilterChain",
                    "authorizeHttpRequests",
                    "UseAuthorization",
                    "AddAuthorization",
                    "RequireAuthorization",
                )
            ):
                result.ambient_controls.append(
                    loc(node, kind="external-policy-candidate", name=name)
                )
        if (
            framework == "next-node"
            and PurePosixPath(path).stem in {"middleware", "proxy"}
            and node.type in FUNCTIONS
        ):
            result.ambient_controls.append(
                loc(
                    node,
                    kind="middleware-candidate",
                    name="Next middleware; matcher and ordering unresolved",
                )
            )

    for node in nodes:
        if node.type not in FUNCTIONS:
            continue
        parents = ancestors(node)
        if any(parent.type in FUNCTIONS for parent in parents):
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        name = text(node.child_by_field_name("name"))
        if not name and node.parent.type == "variable_declarator":
            name = text(node.parent.child_by_field_name("name"))
        owner_node = next((p for p in parents if p.type == "class_declaration"), None)
        owner = text(owner_node.child_by_field_name("name")) if owner_node else ""
        parameters = node.child_by_field_name("parameters")
        parameter_names = []
        if parameters:
            for parameter in parameters.named_children:
                ident = parameter.child_by_field_name("name") or parameter.child_by_field_name(
                    "pattern"
                )
                if parameter.type == "identifier":
                    ident = parameter
                if ident and ident.type == "identifier":
                    parameter_names.append(text(ident))

        def metadata_nodes(declaration):
            if declaration is None:
                return []
            return [
                item
                for child in declaration.named_children
                if child.type in {"modifiers", "attribute_list"}
                for item in child.named_children
                if item.type in {"annotation", "marker_annotation", "attribute"}
            ]

        own_metadata = metadata_nodes(node)
        all_metadata = [*own_metadata, *metadata_nodes(owner_node)]
        metadata_names = {
            text(item.child_by_field_name("name")).split(".")[-1] for item in all_metadata
        }
        own_names = {text(item.child_by_field_name("name")).split(".")[-1] for item in own_metadata}
        endpoint = ""
        exported = any(p.type == "export_statement" for p in parents)
        if framework == "next-node" and exported:
            if (
                name in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
                and PurePosixPath(path).stem == "route"
            ):
                endpoint = f"{name} {PurePosixPath(path).parent}"
            elif re.match(r"\s*['\"]use server['\"]", content.decode("utf-8", errors="replace")):
                endpoint = f"Server Action {name}"
        elif framework == "spring":
            routes = [
                item
                for item in own_metadata
                if text(item.child_by_field_name("name")).split(".")[-1]
                in {
                    "GetMapping",
                    "PostMapping",
                    "PutMapping",
                    "DeleteMapping",
                    "PatchMapping",
                    "RequestMapping",
                }
            ]
            if routes:
                endpoint = text(routes[0])[:200]
        elif framework == "aspnet":
            routes = [
                item
                for item in own_metadata
                if text(item.child_by_field_name("name")).split(".")[-1]
                in {"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"}
            ]
            if routes:
                endpoint = text(routes[0])[:200]
        minimal_authorized = False
        if framework == "aspnet" and node.type == "lambda_expression":
            enclosing_call = next((p for p in parents if p.type == "invocation_expression"), None)
            if enclosing_call and re.search(
                r"\.Map(?:Get|Post|Put|Delete|Patch)$", call_name(enclosing_call)
            ):
                name = f"minimal@{node.start_point.row + 1}"
                endpoint = (
                    text(enclosing_call.child_by_field_name("function"))
                    + " "
                    + text(enclosing_call.child_by_field_name("arguments"))
                    .split(",", 1)[0]
                    .lstrip("(")
                )
                minimal_authorized = any(
                    p.type == "invocation_expression"
                    and call_name(p).endswith(".RequireAuthorization")
                    for p in parents
                )
        if not name:
            continue
        symbol = Symbol(
            name=name,
            owner=owner,
            path=path,
            line=node.start_point.row + 1,
            end_line=node.end_point.row + 1,
            framework=framework,
            parameters=parameter_names,
            endpoint=endpoint,
        )
        if framework == "spring":
            for annotation in all_metadata:
                if text(annotation.child_by_field_name("name")).split(".")[-1] not in {
                    "PreAuthorize",
                    "Secured",
                    "RolesAllowed",
                }:
                    continue
                policy = text(annotation)
                object_bound = (
                    re.search(
                        r"(?:hasPermission\s*\(\s*#\w+|@\w+\.(?:canRead|canWrite|check|visible|canAccess|isOwner)\s*\([^)]*#\w+)",
                        policy,
                    )
                    is not None
                )
                symbol.controls.append(
                    loc(
                        annotation,
                        kind="object-policy" if object_bound else "authorization-policy",
                        name=policy,
                        scope="declarative; runtime configuration unresolved",
                    )
                )
        elif framework == "aspnet":
            if "AllowAnonymous" not in metadata_names and (
                "Authorize" in metadata_names or minimal_authorized
            ):
                symbol.controls.append(
                    loc(
                        node,
                        kind="authorization-policy",
                        name="ASP.NET authorization metadata",
                        scope="declarative; runtime middleware unresolved",
                    )
                )
            if "AllowAnonymous" in own_names or "AllowAnonymous" in metadata_names:
                symbol.controls.append(
                    loc(
                        node,
                        kind="anonymous-policy",
                        name="AllowAnonymous override",
                        scope="explicit anonymous access; resource intent requires review",
                    )
                )
        body_nodes = list(walk(body, cancel, deadline, skip_functions=True))
        if len(body_nodes) > 10000:
            raise OberhauError("Function syntax budget exceeded")
        for item in body_nodes:
            if item.type in CALLS:
                call = call_name(item)
                args = text(item.child_by_field_name("arguments"))
                argument_node = item.child_by_field_name("arguments")
                category = classify_operation(call, framework)
                symbol.calls.append(
                    loc(
                        item,
                        name=call[:200],
                        arguments=redact_source(args)[:1500],
                        identifiers=identifiers(argument_node),
                        argument_identifiers=[
                            identifiers(arg) for arg in argument_node.named_children
                        ]
                        if argument_node
                        else [],
                        offset=item.start_byte,
                        category=category,
                    )
                )
                if re.search(
                    r"(?:authorize|checkOwnership|requireOwner|requirePermission|hasPermission|hasRole|AuthorizeAsync)$",
                    call,
                    re.I,
                ):
                    symbol.controls.append(
                        loc(
                            item,
                            kind="authorization-candidate",
                            name=call,
                            scope="call observed; implementation/dominance unresolved",
                        )
                    )
                if re.search(
                    r"(?:auth|getServerSession|authenticate|requireUser|isAuthenticated)$",
                    call,
                    re.I,
                ):
                    symbol.controls.append(
                        loc(
                            item,
                            kind="identity-candidate",
                            name=call,
                            scope="identity does not demonstrate resource authorization",
                        )
                    )
                if call.endswith(
                    (".parse", ".safeParse", ".validate", ".IsValid", ".escape", ".sanitize")
                ):
                    symbol.controls.append(
                        loc(
                            item,
                            kind="validation-candidate",
                            name=call,
                            scope="validator implementation and sink applicability unresolved",
                        )
                    )
                if (
                    category == "database"
                    and re.search(r"\b(?:ownerId|userId|OwnerId|UserId)\s*[:=]", args)
                    and re.search(r"\b(?:session|user|principal|User)\b", args)
                ):
                    symbol.controls.append(
                        loc(
                            item,
                            kind="object-filter-candidate",
                            name="Identity-shaped resource filter",
                            scope="predicate observed; trusted principal binding unresolved",
                            call_offset=item.start_byte,
                        )
                    )
            if item.type in {"variable_declarator", "assignment_expression"}:
                target = item.child_by_field_name("name") or item.child_by_field_name("left")
                value = item.child_by_field_name("value") or item.child_by_field_name("right")
                if target and value:
                    symbol.transformations.append(
                        loc(
                            item,
                            target=text(target)[:100],
                            inputs=identifiers(value),
                        )
                    )
            shaped = (
                text(item)
                if item.type
                in {
                    "member_expression",
                    "member_access_expression",
                    "method_invocation",
                    "call_expression",
                }
                else ""
            )
            if (
                shaped
                and len(shaped) < 200
                and re.search(
                    r"\b(?:req|request|Request|params|searchParams|cookies|session|process\.env)\b",
                    shaped,
                )
            ):
                symbol.sources.append(
                    loc(item, name=shaped, trust="input-shaped syntax; attacker control unverified")
                )
        if endpoint:
            symbol.sources.extend(
                loc(
                    node,
                    name=p,
                    trust="endpoint parameter; binding and attacker control unverified",
                )
                for p in parameter_names
            )
        # Keep finite records, never silently claim a complete function after truncation.
        if len(symbol.calls) > 128 or len(symbol.sources) > 64 or len(symbol.transformations) > 128:
            result.limitations.append(f"{name}: per-function records truncated")
        symbol.calls = symbol.calls[:128]
        symbol.sources = symbol.sources[:64]
        symbol.transformations = symbol.transformations[:128]
        result.symbols.append(symbol)
    return result


def parse_python(path: str, digest: str, content: bytes) -> FileSummary:
    from oberhau.python_analysis import name_of

    result = FileSummary(path=path, sha256=digest, parser="python:ast")
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        result.limitations.append("Python syntax errors: file excluded")
        return result
    lines = redact_source(content.decode("utf-8", errors="replace")).splitlines()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        symbol = Symbol(
            name=node.name,
            path=path,
            line=node.lineno,
            end_line=node.end_lineno,
            framework="python",
            parameters=[
                a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            ],
        )
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                name = name_of(item.func)
                symbol.calls.append(
                    {
                        "name": name,
                        "line": item.lineno,
                        "code": lines[item.lineno - 1][:500],
                        "category": classify_operation(name, "python"),
                        "arguments": "",
                        "identifiers": sorted(
                            {
                                n.id
                                for arg in item.args
                                for n in ast.walk(arg)
                                if isinstance(n, ast.Name)
                            }
                        ),
                    }
                )
        if len(symbol.calls) > 128:
            result.limitations.append(f"{node.name}: call records truncated")
        symbol.calls = symbol.calls[:128]
        result.symbols.append(symbol)
    result.limitations.append(
        "Python index: top-level functions only; existing source_trace supplies assignment slices"
    )
    return result
