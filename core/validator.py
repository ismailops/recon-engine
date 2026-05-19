"""
Target parsing and validation.

Entry point for all user-supplied targets. Every scanner receives
a validated Target object; raw strings never leave this module.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

from models.target import Target, TargetType


# Loose domain pattern: labels separated by dots, optional trailing dot stripped.
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+[a-zA-Z]{2,}$"
)


def parse_target(raw: str) -> Target:
    """
    Parse and validate a raw user-supplied target string.

    Accepts:
        - Bare domain:  example.com
        - Full URL:     https://example.com/path
        - IPv4/IPv6:    192.168.1.1 or 2001:db8::1

    Returns a fully validated Target.
    Raises ValueError on invalid or unsafe input.
    """
    if not isinstance(raw, str):
        raise ValueError("Target must be a string")

    raw = raw.strip()

    if not raw:
        raise ValueError("Target cannot be empty")

    if len(raw) > 253:
        raise ValueError("Target exceeds maximum allowed length of 253 characters")

    # URL path
    if raw.startswith(("http://", "https://")):
        return _parse_url(raw)

    # IP address
    try:
        addr = ipaddress.ip_address(raw)
        return _build_ip_target(raw, addr)
    except ValueError:
        pass

    # Bare domain
    if _DOMAIN_PATTERN.match(raw):
        return Target(
            raw=raw,
            target_type=TargetType.DOMAIN,
            hostname=raw.lower().rstrip("."),
        )

    raise ValueError(
        f"Cannot parse target {raw!r}. "
        "Supply a domain (example.com), URL (https://example.com), or IP (1.2.3.4)."
    )


def _parse_url(raw: str) -> Target:
    parsed = urlparse(raw)

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not extract hostname from URL: {raw!r}")

    port: Optional[int] = parsed.port

    # Validate extracted hostname recursively
    inner = parse_target(hostname)

    return Target(
        raw=raw,
        target_type=TargetType.URL,
        hostname=inner.hostname,
        scheme=parsed.scheme,
        port=port,
        path=parsed.path or None,
    )


def _build_ip_target(raw: str, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Target:
    return Target(
        raw=raw,
        target_type=TargetType.IP,
        hostname=str(addr),
    )
