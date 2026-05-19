"""
JSON export for scan sessions.

Serialises a ScanSession to a structured JSON file in the outputs/ directory.
All datetime values are rendered as ISO 8601 strings for maximum compatibility.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from models.results import ScanSession

logger = logging.getLogger(__name__)

_OUTPUT_DIR = Path("outputs")


def export_session_json(session: ScanSession, output_dir: Path = _OUTPUT_DIR) -> Path:
    """
    Write a ScanSession to a JSON file.

    File is named <target>_<started_at_date>.json.
    Returns the path to the written file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    date_tag = session.started_at.strftime("%Y%m%d_%H%M%S")
    safe_target = _sanitise_filename(session.target)
    file_path = output_dir / f"{safe_target}_{date_tag}.json"

    payload = _build_payload(session)

    with open(file_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str, ensure_ascii=False)

    logger.info("JSON export written to %s", file_path)
    return file_path


def _build_payload(session: ScanSession) -> dict:
    return {
        "meta": {
            "target": session.target,
            "started_at": session.started_at.isoformat(),
            "finished_at": session.finished_at.isoformat() if session.finished_at else None,
            "duration_seconds": session.duration_seconds,
            "tool": "recon-engine",
        },
        "subdomains": [
            {
                "subdomain": r.subdomain,
                "source": r.source,
                "resolved": r.resolved,
                "ip_address": r.ip_address,
                "discovered_at": r.discovered_at.isoformat(),
            }
            for r in session.subdomains
        ],
        "ports": [
            {
                "port": r.port,
                "protocol": r.protocol,
                "state": r.state,
                "service": r.service,
                "banner": r.banner,
                "scanned_at": r.scanned_at.isoformat(),
            }
            for r in session.ports
        ],
        "http_fingerprints": [
            {
                "url": r.url,
                "status_code": r.status_code,
                "server": r.server,
                "content_type": r.content_type,
                "x_powered_by": r.x_powered_by,
                "technologies": r.technologies,
                "redirect_url": r.redirect_url,
                "response_time_ms": r.response_time_ms,
                "fingerprinted_at": r.fingerprinted_at.isoformat(),
            }
            for r in session.http_fingerprints
        ],
    }


def _sanitise_filename(name: str) -> str:
    """Replace characters unsafe for filenames with underscores."""
    safe = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in name)
    return safe[:64]
