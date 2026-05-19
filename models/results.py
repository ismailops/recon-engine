"""
Data models for scan results.

Each scanner module produces one of these typed result objects.
They are validated before storage and before export.
"""

from __future__ import annotations

import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, field_validator


class SubdomainResult(BaseModel):
    """A single subdomain discovered during enumeration."""

    subdomain: str
    source: str
    resolved: bool = False
    ip_address: Optional[str] = None
    discovered_at: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)

    @field_validator("subdomain")
    @classmethod
    def subdomain_must_be_printable(cls, value: str) -> str:
        value = value.strip().lower()
        if not value:
            raise ValueError("Subdomain cannot be empty")
        return value


class PortResult(BaseModel):
    """Result for a single port probe."""

    port: int
    protocol: str = "tcp"
    state: str  # "open" | "closed" | "filtered"
    service: Optional[str] = None
    banner: Optional[str] = None
    scanned_at: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)

    @field_validator("port")
    @classmethod
    def port_in_range(cls, value: int) -> int:
        if not (1 <= value <= 65535):
            raise ValueError(f"Invalid port: {value}")
        return value

    @field_validator("state")
    @classmethod
    def state_must_be_known(cls, value: str) -> str:
        allowed = {"open", "closed", "filtered"}
        if value not in allowed:
            raise ValueError(f"Unknown port state: {value!r}")
        return value


class HTTPFingerprint(BaseModel):
    """HTTP-level information gathered from a single endpoint."""

    url: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    x_powered_by: Optional[str] = None
    technologies: List[str] = []
    headers: Dict[str, str] = {}
    redirect_url: Optional[str] = None
    response_time_ms: Optional[float] = None
    fingerprinted_at: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)


class ScanSession(BaseModel):
    """
    Top-level container for an entire scan run.

    Stored once per invocation; child results reference the session id.
    """

    target: str
    started_at: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)
    finished_at: Optional[datetime.datetime] = None
    subdomains: List[SubdomainResult] = []
    ports: List[PortResult] = []
    http_fingerprints: List[HTTPFingerprint] = []
    notes: Optional[str] = None

    def mark_finished(self) -> None:
        self.finished_at = datetime.datetime.now(datetime.timezone.utc)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.finished_at is None:
            return None
        delta = self.finished_at - self.started_at
        return round(delta.total_seconds(), 2)
