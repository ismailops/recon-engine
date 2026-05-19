"""
HTTP fingerprinting scanner.

Probes HTTP and HTTPS endpoints to collect server headers, infer technologies,
and measure response characteristics. No active exploitation — purely passive
observation of what the server voluntarily returns.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple

import aiohttp

from models.results import HTTPFingerprint
from models.target import Target, TargetType

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)
_MAX_REDIRECTS = 5
_USER_AGENT = "recon-engine/1.0 (authorized security assessment)"

# Technology fingerprinting rules: header → {value_fragment: technology_name}
# Kept intentionally conservative — only high-confidence signals.
_HEADER_TECH_RULES: List[Tuple[str, str, str]] = [
    ("server", "apache", "Apache HTTP Server"),
    ("server", "nginx", "Nginx"),
    ("server", "iis", "Microsoft IIS"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "litespeed", "LiteSpeed"),
    ("server", "openresty", "OpenResty"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express.js"),
    ("x-powered-by", "next.js", "Next.js"),
    ("x-generator", "wordpress", "WordPress"),
    ("x-generator", "drupal", "Drupal"),
    ("x-drupal-cache", "", "Drupal"),
    ("x-shopify-stage", "", "Shopify"),
    ("x-wix-request-id", "", "Wix"),
    ("cf-ray", "", "Cloudflare"),
    ("x-amz-cf-id", "", "Amazon CloudFront"),
    ("x-cache", "cloudfront", "Amazon CloudFront"),
    ("via", "varnish", "Varnish Cache"),
    ("x-varnish", "", "Varnish Cache"),
]


async def fingerprint_http(target: Target) -> List[HTTPFingerprint]:
    """
    Fingerprint all reasonable HTTP/HTTPS endpoints for the target.

    For a bare domain or IP, probes both http:// and https://.
    For a URL target, probes only the specified scheme and host.
    """
    endpoints = _build_endpoints(target)
    logger.info("HTTP fingerprinting %d endpoint(s) for %s", len(endpoints), target.hostname)

    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=_REQUEST_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
    ) as session:
        tasks = [_fingerprint_endpoint(session, url) for url in endpoints]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r is not None]


def _build_endpoints(target: Target) -> List[str]:
    """Build the list of URLs to probe based on target type."""
    if target.target_type == TargetType.URL and target.scheme:
        return [f"{target.scheme}://{target.hostname}"]

    return [
        f"http://{target.hostname}",
        f"https://{target.hostname}",
    ]


async def _fingerprint_endpoint(
    session: aiohttp.ClientSession, url: str
) -> Optional[HTTPFingerprint]:
    """
    Perform a single HTTP GET and extract fingerprint data.

    Returns None if the endpoint is unreachable.
    """
    start = time.monotonic()
    try:
        async with session.get(
            url,
            allow_redirects=True,
            max_redirects=_MAX_REDIRECTS,
        ) as response:
            elapsed_ms = (time.monotonic() - start) * 1000

            headers_lower: Dict[str, str] = {
                k.lower(): v for k, v in response.headers.items()
            }

            technologies = _detect_technologies(headers_lower)
            redirect_url: Optional[str] = None
            if str(response.url) != url:
                redirect_url = str(response.url)

            return HTTPFingerprint(
                url=url,
                status_code=response.status,
                server=headers_lower.get("server"),
                content_type=headers_lower.get("content-type"),
                x_powered_by=headers_lower.get("x-powered-by"),
                technologies=technologies,
                headers=_sanitise_headers(headers_lower),
                redirect_url=redirect_url,
                response_time_ms=round(elapsed_ms, 2),
            )

    except aiohttp.ClientConnectorError:
        logger.debug("Connection refused or DNS failure for %s", url)
        return None
    except asyncio.TimeoutError:
        logger.debug("Timeout connecting to %s", url)
        return None
    except aiohttp.TooManyRedirects:
        logger.debug("Too many redirects for %s", url)
        return None
    except Exception as exc:
        logger.debug("Unexpected error fingerprinting %s: %s", url, exc)
        return None


def _detect_technologies(headers: Dict[str, str]) -> List[str]:
    """
    Infer server-side technologies from response headers.

    Returns a deduplicated list of technology names.
    """
    detected: set[str] = set()

    for header_name, value_fragment, tech_name in _HEADER_TECH_RULES:
        header_value = headers.get(header_name, "")
        if header_value and (not value_fragment or value_fragment in header_value.lower()):
            detected.add(tech_name)

    return sorted(detected)


def _sanitise_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Return a subset of headers safe to store.

    Drops headers that may contain session tokens or internal identifiers
    that have no forensic value for fingerprinting.
    """
    skip = {
        "set-cookie",
        "cookie",
        "authorization",
        "proxy-authorization",
        "www-authenticate",
    }
    return {k: v for k, v in headers.items() if k not in skip}
