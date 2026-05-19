"""
Scan engine orchestrator.

Coordinates the execution of individual scanner modules and persists results
to the database. Callers interact with this module; they do not invoke
scanners directly.
"""

from __future__ import annotations

import datetime
import logging
from typing import List, Optional

from core.validator import parse_target
from database.store import ScanStore
from models.results import HTTPFingerprint, PortResult, ScanSession, SubdomainResult
from models.target import Target
from scanners.subdomain import enumerate_subdomains
from scanners.ports import scan_ports
from scanners.http_fingerprint import fingerprint_http

logger = logging.getLogger(__name__)


class ReconEngine:
    """
    Orchestrates a full or partial recon run against a validated target.

    Usage:
        engine = ReconEngine(store)
        session = await engine.run_full_scan("example.com")
    """

    def __init__(self, store: ScanStore) -> None:
        self._store = store

    async def run_full_scan(
        self,
        raw_target: str,
        port_list: Optional[List[int]] = None,
    ) -> ScanSession:
        """
        Execute all scanner modules in sequence and persist results.

        Order: subdomain enumeration → port scan → HTTP fingerprint.
        Results are committed after each phase so partial data is never lost.
        """
        target = parse_target(raw_target)
        session = ScanSession(target=target.hostname)
        session_id = self._store.create_session(session)

        logger.info("Starting full scan for %s (session %s)", target.hostname, session_id)

        # Phase 1: subdomain enumeration
        subdomains = await enumerate_subdomains(target)
        session.subdomains = subdomains
        self._store.save_subdomains(session_id, subdomains)
        logger.info("Found %d subdomains", len(subdomains))

        # Phase 2: port scanning
        ports = await scan_ports(target, port_list=port_list)
        session.ports = ports
        self._store.save_ports(session_id, ports)
        open_count = sum(1 for p in ports if p.state == "open")
        logger.info("Port scan complete: %d open of %d probed", open_count, len(ports))

        # Phase 3: HTTP fingerprinting
        fingerprints = await fingerprint_http(target)
        session.http_fingerprints = fingerprints
        self._store.save_fingerprints(session_id, fingerprints)
        logger.info("HTTP fingerprinting complete for %d endpoints", len(fingerprints))

        session.mark_finished()
        self._store.finish_session(session_id, session.finished_at)

        logger.info(
            "Scan finished in %.2fs", session.duration_seconds or 0.0
        )
        return session

    async def run_subdomain_scan(self, raw_target: str) -> ScanSession:
        """Run only subdomain enumeration."""
        target = parse_target(raw_target)
        session = ScanSession(target=target.hostname)
        session_id = self._store.create_session(session)

        subdomains = await enumerate_subdomains(target)
        session.subdomains = subdomains
        self._store.save_subdomains(session_id, subdomains)

        session.mark_finished()
        self._store.finish_session(session_id, session.finished_at)
        return session

    async def run_port_scan(
        self,
        raw_target: str,
        port_list: Optional[List[int]] = None,
    ) -> ScanSession:
        """Run only port scanning."""
        target = parse_target(raw_target)
        session = ScanSession(target=target.hostname)
        session_id = self._store.create_session(session)

        ports = await scan_ports(target, port_list=port_list)
        session.ports = ports
        self._store.save_ports(session_id, ports)

        session.mark_finished()
        self._store.finish_session(session_id, session.finished_at)
        return session
