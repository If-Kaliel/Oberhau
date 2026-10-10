from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from oberhau.core import OberhauError


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_hosts: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    automation_allowed: bool = False
    reviewed: bool = False
    revision: int = Field(default=1, ge=1)
    requests_per_minute: int = Field(default=10, ge=1, le=120)
    request_budget: int = Field(default=50, ge=1, le=1000)
    concurrency: int = Field(default=1, ge=1, le=4)
    allowed_categories: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def exact_hosts(self) -> Policy:
        for host in self.allowed_hosts + self.excluded_hosts:
            if not host or any(c in host for c in "/:*@ ") or host != host.lower():
                raise ValueError("Scope requires exact lowercase hostnames; no wildcards")
        return self

    def authorize(self, url: str, category: str, revision: int, approved: bool) -> None:
        target = urlsplit(url)
        host = target.hostname
        if target.scheme not in ("http", "https") or target.username or target.password:
            raise OberhauError("Invalid target URL")
        if not self.reviewed or revision != self.revision or not approved:
            raise OberhauError("Current policy review and explicit human approval required")
        if host in self.excluded_hosts or host not in self.allowed_hosts:
            raise OberhauError("Target outside authorized scope")
        if category not in self.allowed_categories or not self.automation_allowed:
            raise OberhauError("This testing category or automation is not permitted")
        try:
            address = ipaddress.ip_address(host or "")
        except ValueError:
            address = None
        if address and (address.is_multicast or address.is_unspecified):
            raise OberhauError("Unsafe target address")


def block_active() -> None:
    raise OberhauError(
        "Active testing is unavailable. Use offline analysis or the bundled laboratory."
    )
