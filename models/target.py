"""
Data models for scan targets.

Defines the validated input structure consumed by all scanner modules.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator, model_validator


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"


class Target(BaseModel):
    """
    Represents a validated scan target.

    All scanners operate on a Target instance, never on raw strings.
    This ensures input validation happens exactly once, at the boundary.
    """

    raw: str
    target_type: TargetType
    hostname: str
    scheme: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def hostname_must_be_safe(cls, value: str) -> str:
        """
        Reject hostnames containing shell metacharacters or path traversal sequences.
        This is a defense-in-depth check; actual shell calls should never use
        user-supplied strings directly.
        """
        forbidden = set(';|&$`(){}[]<>\\\'"\n\r\t ')
        if any(ch in forbidden for ch in value):
            raise ValueError(f"Hostname contains forbidden characters: {value!r}")
        if ".." in value:
            raise ValueError("Path traversal sequence detected in hostname")
        return value.lower()

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and not (1 <= value <= 65535):
            raise ValueError(f"Port out of valid range: {value}")
        return value

    @property
    def display(self) -> str:
        """Human-readable label used in CLI output and reports."""
        return self.hostname
