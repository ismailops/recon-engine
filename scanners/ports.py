"""
Async TCP port scanner.

Uses asyncio streams for concurrent probing. All connections are made
with an explicit timeout to prevent indefinite hangs. No raw sockets,
no ICMP, no OS-level privilege requirements.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from models.results import PortResult
from models.target import Target

logger = logging.getLogger(__name__)

# Well-known service names for common ports
_SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    8888: "jupyter",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Default port list covers common attack surface without being exhaustive
DEFAULT_PORTS: List[int] = sorted(_SERVICE_MAP.keys())

_CONNECT_TIMEOUT: float = 2.0
_MAX_CONCURRENT: int = 100


async def scan_ports(
    target: Target,
    port_list: Optional[List[int]] = None,
) -> List[PortResult]:
    """
    Probe a list of TCP ports on the target host concurrently.

    Returns a list of PortResult objects sorted by port number.
    Always returns results for every probed port (open, closed, or filtered).
    """
    ports_to_scan = port_list if port_list is not None else DEFAULT_PORTS
    host = target.hostname

    logger.info(
        "Port scan starting: host=%s, ports=%d, concurrency=%d",
        host,
        len(ports_to_scan),
        _MAX_CONCURRENT,
    )

    semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
    tasks = [_probe_port(host, port, semaphore) for port in ports_to_scan]
    results: List[PortResult] = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r.state == "open"]
    logger.info(
        "Port scan complete: %d/%d open", len(open_ports), len(ports_to_scan)
    )

    return sorted(results, key=lambda r: r.port)


async def _probe_port(host: str, port: int, semaphore: asyncio.Semaphore) -> PortResult:
    """
    Attempt a TCP connection to host:port.

    Connection refused → closed.
    Timeout or other network error → filtered.
    Successful connect → open.
    """
    async with semaphore:
        service = _SERVICE_MAP.get(port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=_CONNECT_TIMEOUT,
            )
            # Attempt a brief banner grab (best-effort)
            banner = await _grab_banner(reader)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
            )

        except ConnectionRefusedError:
            return PortResult(port=port, state="closed", service=service)

        except (asyncio.TimeoutError, OSError):
            return PortResult(port=port, state="filtered", service=service)

        except Exception as exc:
            logger.debug("Unexpected error probing %s:%d — %s", host, port, exc)
            return PortResult(port=port, state="filtered", service=service)


async def _grab_banner(reader: asyncio.StreamReader) -> Optional[str]:
    """
    Attempt to read up to 256 bytes from an open connection.

    Returns a sanitised ASCII string, or None if no data arrives within 1 second.
    """
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=1.0)
        if data:
            # Decode safely, drop non-printable bytes
            text = data.decode("ascii", errors="replace").strip()
            # Truncate and strip control characters
            sanitised = "".join(ch for ch in text if ch.isprintable() or ch == " ")
            return sanitised[:200] if sanitised else None
    except Exception:
        pass
    return None
