"""
Passive subdomain enumeration.

Currently uses the crt.sh certificate transparency log API.
All enumeration is strictly passive — no DNS brute force, no active probing
beyond optional A-record resolution after discovery.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import List, Optional

import aiohttp

from models.results import SubdomainResult
from models.target import Target

logger = logging.getLogger(__name__)

_CRTSH_URL = "https://crt.sh/"
_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)
_MAX_RESULTS = 500


async def enumerate_subdomains(target: Target) -> List[SubdomainResult]:
    """
    Discover subdomains for the given target using passive sources.

    Returns a deduplicated, sorted list of SubdomainResult objects.
    Never raises; errors are logged and an empty list is returned.
    """
    logger.info("Starting subdomain enumeration for %s", target.hostname)

    results: List[SubdomainResult] = []

    crtsh_results = await _query_crtsh(target.hostname)
    results.extend(crtsh_results)

    deduplicated = _deduplicate(results)
    resolved = await _resolve_all(deduplicated)

    logger.info(
        "Subdomain enumeration complete: %d unique subdomains found", len(resolved)
    )
    return sorted(resolved, key=lambda r: r.subdomain)


async def _query_crtsh(domain: str) -> List[SubdomainResult]:
    """
    Fetch certificate transparency entries from crt.sh.

    Returns raw (unresolved) SubdomainResult objects.
    """
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        async with aiohttp.ClientSession(timeout=_REQUEST_TIMEOUT) as session:
            async with session.get(_CRTSH_URL, params=params, ssl=True) as response:
                if response.status != 200:
                    logger.warning(
                        "crt.sh returned HTTP %d for %s", response.status, domain
                    )
                    return []

                data = await response.json(content_type=None)

    except aiohttp.ClientError as exc:
        logger.error("crt.sh request failed: %s", exc)
        return []
    except asyncio.TimeoutError:
        logger.error("crt.sh request timed out for %s", domain)
        return []
    except Exception as exc:
        logger.error("Unexpected error querying crt.sh: %s", exc)
        return []

    return _parse_crtsh_response(data, domain)


def _parse_crtsh_response(data: list, base_domain: str) -> List[SubdomainResult]:
    """
    Extract subdomain names from a crt.sh JSON response.

    Skips wildcard entries and entries that are not subdomains of base_domain.
    Limits output to _MAX_RESULTS to prevent memory issues on very large result sets.
    """
    seen: set[str] = set()
    results: List[SubdomainResult] = []

    for entry in data:
        name_value: Optional[str] = entry.get("name_value")
        if not name_value:
            continue

        # crt.sh may return newline-separated SANs in a single entry
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if not name:
                continue
            if not name.endswith(f".{base_domain}") and name != base_domain:
                continue
            if name in seen:
                continue

            seen.add(name)
            results.append(
                SubdomainResult(subdomain=name, source="crt.sh")
            )

            if len(results) >= _MAX_RESULTS:
                logger.warning(
                    "crt.sh result cap (%d) reached for %s; truncating",
                    _MAX_RESULTS,
                    base_domain,
                )
                return results

    return results


def _deduplicate(results: List[SubdomainResult]) -> List[SubdomainResult]:
    """Remove duplicate subdomains, preserving the first occurrence."""
    seen: set[str] = set()
    unique: List[SubdomainResult] = []
    for result in results:
        if result.subdomain not in seen:
            seen.add(result.subdomain)
            unique.append(result)
    return unique


async def _resolve_all(results: List[SubdomainResult]) -> List[SubdomainResult]:
    """
    Attempt DNS A-record resolution for each subdomain.

    Resolution is fire-and-forget; failures mark resolved=False without
    removing the subdomain from results.
    """
    tasks = [_resolve_one(result) for result in results]
    return await asyncio.gather(*tasks)


async def _resolve_one(result: SubdomainResult) -> SubdomainResult:
    """Resolve a single subdomain in an executor to avoid blocking the event loop."""
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(
            None, socket.gethostbyname, result.subdomain
        )
        result.resolved = True
        result.ip_address = ip
    except socket.gaierror:
        result.resolved = False
    return result
