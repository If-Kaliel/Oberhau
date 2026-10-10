from __future__ import annotations

import ast
import re
import time
from collections.abc import Callable
from pathlib import Path
from threading import Event

from oberhau.core import Cancelled, Finding, Limits
from oberhau.security import confined, redact, redact_source


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return call_name(node.value) + "." + node.attr
    return ""


class BuiltinScanner:
    identifier = "builtin"
    version = "0.1.0"
    license = "MIT"
    categories = ["unsafe-code", "secrets", "configuration"]
    network = False
    active = False

    def scan(
        self,
        root: Path,
        paths: list[str],
        cancel: Event,
        limits: Limits,
        progress: Callable[[str], None],
        categories: list[str] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        selected = categories or self.categories
        deadline = time.monotonic() + limits.timeout
        for index, relative in enumerate(paths):
            if cancel.is_set():
                raise Cancelled()
            if time.monotonic() > deadline:
                from oberhau.core import OberhauError

                raise OberhauError("builtin: timeout")
            path = confined(root, relative)
            if path.suffix not in {
                ".py",
                ".js",
                ".ts",
                ".jsx",
                ".tsx",
                ".yaml",
                ".yml",
                ".json",
                ".env",
                ".txt",
                ".tf",
            } and path.name not in {"Dockerfile", ".env"}:
                continue
            content = path.read_bytes()
            if b"\0" in content or len(content) > limits.max_file_bytes:
                continue
            text = content.decode("utf-8", errors="replace")
            lines = text.splitlines()
            safe_lines = redact_source(text).splitlines()

            def add(
                rule: str,
                category: str,
                title: str,
                line: int,
                cwe: str,
                severity: str = "medium",
                confidence: float = 0.65,
                relative: str = relative,
                lines: list[str] = safe_lines,
            ) -> None:
                findings.append(
                    Finding(
                        scanner=self.identifier,
                        rule=rule,
                        category=category,
                        title=title,
                        path=relative,
                        line=line,
                        end_line=line,
                        cwe=[cwe],
                        severity=severity,
                        confidence=confidence,
                        context=redact("\n".join(lines[max(0, line - 3) : line + 2])),
                        explanation="Heuristic static warning. Review protective controls, input provenance, reachability, and impact before confirmation.",
                    )
                )

            if path.suffix == ".py" and "unsafe-code" in selected:
                try:
                    tree = ast.parse(text)
                except (SyntaxError, ValueError) as error:
                    progress(
                        f"{relative}: Python parse error at line {getattr(error, 'lineno', '?')}; AST coverage skipped"
                    )
                    tree = None
                if tree:
                    aliases: dict[str, str] = {}
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                aliases[alias.asname or alias.name] = alias.name
                        elif isinstance(node, ast.ImportFrom):
                            for alias in node.names:
                                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
                    for node in ast.walk(tree):
                        if not isinstance(node, ast.Call):
                            continue
                        name = call_name(node.func)
                        head, _, tail = name.partition(".")
                        name = aliases.get(head, head) + ("." + tail if tail else "")
                        if name in {"eval", "exec"}:
                            add(
                                "python-dynamic-code",
                                "unsafe-code",
                                "Dynamic code evaluation",
                                node.lineno,
                                "CWE-95",
                                "high",
                            )
                        elif name in {"os.system", "os.popen"} or (
                            name.startswith("subprocess.")
                            and any(
                                k.arg == "shell"
                                and isinstance(k.value, ast.Constant)
                                and k.value.value is True
                                for k in node.keywords
                            )
                        ):
                            add(
                                "python-shell",
                                "unsafe-code",
                                "Shell command execution boundary",
                                node.lineno,
                                "CWE-78",
                                "high",
                            )
                        elif name in {"pickle.loads", "pickle.load", "yaml.load"}:
                            add(
                                "python-deserialization",
                                "unsafe-code",
                                "Potential unsafe deserialization",
                                node.lineno,
                                "CWE-502",
                                "high",
                            )
                        elif name in {"hashlib.md5", "hashlib.sha1"}:
                            add(
                                "python-weak-hash",
                                "unsafe-code",
                                "Weak hash in a potentially sensitive context",
                                node.lineno,
                                "CWE-328",
                                "low",
                                0.5,
                            )
                        elif (
                            name.endswith((".execute", ".executemany"))
                            and node.args
                            and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp))
                        ):
                            add(
                                "python-sql-format",
                                "unsafe-code",
                                "Formatted query at database execution",
                                node.lineno,
                                "CWE-89",
                                "high",
                                0.8,
                            )
            for number, line in enumerate(lines, 1):
                if "secrets" in selected and (
                    re.search(
                        r"(?i)\b(password|secret|token|api_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]", line
                    )
                    or re.search(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b|BEGIN .*PRIVATE KEY", line)
                ):
                    add(
                        "secret-literal",
                        "secrets",
                        "Possible embedded credential (value redacted)",
                        number,
                        "CWE-798",
                        "high",
                        0.65,
                    )
                if "configuration" in selected and (
                    re.search(r"\bDEBUG\s*=\s*True|\bdebug\s*=\s*True", line)
                    or re.search(r"\bprivileged\s*:\s*true", line)
                    or (path.name == "Dockerfile" and re.match(r"\s*USER\s+root\b", line))
                ):
                    add(
                        "insecure-configuration",
                        "configuration",
                        "Debug mode or privileged execution configured",
                        number,
                        "CWE-16",
                        "medium",
                        0.8,
                    )
            if index % 25 == 0:
                progress(f"builtin: inspected {index + 1}/{len(paths)} indexed files")
        return findings
