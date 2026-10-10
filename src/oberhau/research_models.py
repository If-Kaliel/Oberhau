"""Serializable research evidence; hypotheses are never exploitation verdicts."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ResearchLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_nodes: int = Field(default=20000, ge=100, le=100000)
    max_symbols: int = Field(default=5000, ge=1, le=20000)
    max_depth: int = Field(default=4, ge=1, le=8)
    max_visits: int = Field(default=64, ge=1, le=256)
    max_index_bytes: int = Field(default=32_000_000, ge=1000, le=100_000_000)
    parser_timeout_seconds: int = Field(default=10, ge=1, le=60)
    parser_memory_mib: int = Field(default=512, ge=128, le=2048)


class EvidenceNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    kind: Literal[
        "project",
        "commit",
        "file",
        "function",
        "endpoint",
        "source",
        "transformation",
        "operation",
        "control",
        "gap",
        "scanner",
        "hypothesis",
    ]
    label: str
    path: str = ""
    line: int = Field(default=1, ge=1)
    sha256: str = ""
    code: str = ""


class EvidenceEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    target: str
    relation: str


class EvidenceGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nodes: list[EvidenceNode] = Field(default_factory=list)
    edges: list[EvidenceEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_edges(self):
        ids = {node.id for node in self.nodes}
        if len(ids) != len(self.nodes) or any(
            e.source not in ids or e.target not in ids for e in self.edges
        ):
            raise ValueError("Evidence graph contains duplicate nodes or dangling references")
        return self


class GraphBuilder:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.nodes: dict[str, EvidenceNode] = {}
        self.edges: dict[tuple, EvidenceEdge] = {}

    def add(self, kind: str, label: str, path="", line=1, sha256="", code="") -> str:
        from oberhau.core import OberhauError
        from oberhau.security import redact

        identity = f"{kind}|{path}|{line}|{label}"
        identifier = hashlib.sha256(identity.encode()).hexdigest()[:24]
        if identifier not in self.nodes and len(self.nodes) >= self.maximum:
            raise OberhauError("Research graph node budget exceeded")
        self.nodes[identifier] = EvidenceNode(
            id=identifier,
            kind=kind,
            label=redact(label),
            path=path,
            line=line,
            sha256=sha256,
            code=redact(code)[:500],
        )
        return identifier

    def link(self, source: str, target: str, relation: str) -> None:
        from oberhau.core import OberhauError

        if len(self.edges) >= self.maximum * 4:
            raise OberhauError("Research graph edge budget exceeded")
        self.edges[(source, target, relation)] = EvidenceEdge(
            source=source, target=target, relation=relation
        )

    def build(self) -> EvidenceGraph:
        return EvidenceGraph(nodes=list(self.nodes.values()), edges=list(self.edges.values()))


class Symbol(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    owner: str = ""
    path: str
    line: int
    end_line: int
    framework: str
    parameters: list[str] = Field(default_factory=list)
    endpoint: str = ""
    calls: list[dict] = Field(default_factory=list)
    controls: list[dict] = Field(default_factory=list)
    sources: list[dict] = Field(default_factory=list)
    transformations: list[dict] = Field(default_factory=list)


class FileSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    sha256: str
    parser: str
    symbols: list[Symbol] = Field(default_factory=list)
    imports: dict[str, dict] = Field(default_factory=dict)
    exports: dict[str, str] = Field(default_factory=dict)
    ambient_controls: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule: str
    title: str
    operation: str
    path: str
    line: int
    endpoint: str
    inputs: list[dict]
    execution_path: list[str]
    controls: list[dict]
    missing_controls: list[str]
    limitations: list[str]
    confirmation: list[str]
    evidence_ids: list[str]
    confidence: float = Field(ge=0, le=1)
    severity: str = "medium"
