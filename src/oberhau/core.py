from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def now() -> str:
    return datetime.now(UTC).isoformat()


def data_home() -> Path:
    configured = os.environ.get("OBERHAU_HOME")
    return (
        Path(configured) if configured else Path(os.getenv("LOCALAPPDATA", Path.home())) / "Oberhau"
    )


class Status(StrEnum):
    DETECTED = "Detected"
    SUSPECTED = "Suspected"
    INVESTIGATING = "Under Investigation"
    PENDING = "Reproduction Pending"
    REPRODUCED = "Locally Reproduced"
    VERIFIED = "Human Verified"
    READY = "Report Ready"
    SUBMITTED = "Submitted"
    ACCEPTED = "Accepted"
    DUPLICATE = "Duplicate"
    INFORMATIVE = "Informative"
    NA = "Not Applicable"
    FALSE_POSITIVE = "False Positive"
    FIXED = "Fixed"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scanner: str
    rule: str
    category: str
    title: str
    path: str
    line: int = Field(default=1, ge=1)
    end_line: int = Field(default=1, ge=1)
    severity: str = "medium"
    confidence: float = Field(default=0.6, ge=0, le=1)
    cwe: list[str] = Field(default_factory=list)
    advisories: list[str] = Field(default_factory=list)
    explanation: str = "Static warning; reachability and impact remain unverified."
    context: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    status: Status = Status.DETECTED

    def fingerprint(self, project_id: int) -> str:
        # Only explicitly equivalent bundled rules correlate across engines.
        equivalents = {
            ("builtin", "python-dynamic-code"): "dynamic-code",
            ("semgrep", "oberhau-python-eval"): "dynamic-code",
        }
        family = equivalents.get(
            (self.scanner, self.rule.split(".")[-1]), f"{self.scanner}:{self.rule}"
        )
        identity = f"{project_id}|{family}|{self.path}|{self.line}"
        return hashlib.sha256(identity.encode()).hexdigest()


class Limits(BaseModel):
    timeout: int = Field(default=180, ge=1, le=3600)
    max_file_bytes: int = Field(default=2_000_000, ge=100, le=20_000_000)
    max_files: int = Field(default=20_000, ge=1, le=100_000)
    max_total_bytes: int = Field(default=200_000_000, ge=1000, le=2_000_000_000)
    max_output_bytes: int = Field(default=20_000_000, ge=1000, le=100_000_000)
    parallelism: int = Field(default=2, ge=1, le=8)


class DraftText(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=4000)
    explanation: str = Field(max_length=6000)
    remediation: str = Field(max_length=4000)
    limitations: str = Field(max_length=4000)


class Cancelled(Exception):
    """Cooperative cancellation, never treated as a successful scan."""


class OberhauError(Exception):
    """An actionable application error."""
