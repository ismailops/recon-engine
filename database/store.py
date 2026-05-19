"""
SQLite storage layer.

Provides a synchronous interface over sqlite3 for storing and retrieving
scan results. The engine is async; the store is sync and called from
the engine's synchronous wrapper methods only.

Connection handling uses context managers throughout to guarantee
that transactions are committed or rolled back cleanly.
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
from pathlib import Path
from typing import List, Optional

from database.schema import SCHEMA_SQL
from models.results import HTTPFingerprint, PortResult, ScanSession, SubdomainResult

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path("outputs/recon.db")


class ScanStore:
    """
    Thin wrapper over an SQLite database.

    Instantiate once per process; the underlying connection is reused.
    Thread-safety is not guaranteed — use one ScanStore per thread.
    """

    def __init__(self, db_path: Path = _DEFAULT_DB_PATH) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._conn = self._connect()
        self._apply_schema()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _apply_schema(self) -> None:
        with self._conn:
            self._conn.executescript(SCHEMA_SQL)
        logger.debug("Schema applied to %s", self._db_path)

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(self, session: ScanSession) -> int:
        """Insert a new scan session record and return its auto-assigned id."""
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO scan_sessions (target, started_at, notes) VALUES (?, ?, ?)",
                (session.target, session.started_at.isoformat(), session.notes),
            )
        return cursor.lastrowid  # type: ignore[return-value]

    def finish_session(
        self, session_id: int, finished_at: Optional[datetime.datetime]
    ) -> None:
        ts = finished_at.isoformat() if finished_at else None
        with self._conn:
            self._conn.execute(
                "UPDATE scan_sessions SET finished_at = ? WHERE id = ?",
                (ts, session_id),
            )

    def get_session_by_target(self, target: str) -> Optional[dict]:
        """Return the most recent session for a target, or None."""
        row = self._conn.execute(
            "SELECT * FROM scan_sessions WHERE target = ? ORDER BY id DESC LIMIT 1",
            (target,),
        ).fetchone()
        return dict(row) if row else None

    def list_sessions(self) -> List[dict]:
        rows = self._conn.execute(
            "SELECT * FROM scan_sessions ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Subdomain results
    # ------------------------------------------------------------------

    def save_subdomains(self, session_id: int, results: List[SubdomainResult]) -> None:
        rows = [
            (
                session_id,
                r.subdomain,
                r.source,
                int(r.resolved),
                r.ip_address,
                r.discovered_at.isoformat(),
            )
            for r in results
        ]
        with self._conn:
            self._conn.executemany(
                """INSERT INTO subdomains
                   (session_id, subdomain, source, resolved, ip_address, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                rows,
            )

    def get_subdomains(self, session_id: int) -> List[SubdomainResult]:
        rows = self._conn.execute(
            "SELECT * FROM subdomains WHERE session_id = ? ORDER BY subdomain",
            (session_id,),
        ).fetchall()
        return [
            SubdomainResult(
                subdomain=r["subdomain"],
                source=r["source"],
                resolved=bool(r["resolved"]),
                ip_address=r["ip_address"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Port results
    # ------------------------------------------------------------------

    def save_ports(self, session_id: int, results: List[PortResult]) -> None:
        rows = [
            (
                session_id,
                r.port,
                r.protocol,
                r.state,
                r.service,
                r.banner,
                r.scanned_at.isoformat(),
            )
            for r in results
        ]
        with self._conn:
            self._conn.executemany(
                """INSERT INTO port_results
                   (session_id, port, protocol, state, service, banner, scanned_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )

    def get_ports(self, session_id: int) -> List[PortResult]:
        rows = self._conn.execute(
            "SELECT * FROM port_results WHERE session_id = ? ORDER BY port",
            (session_id,),
        ).fetchall()
        return [
            PortResult(
                port=r["port"],
                protocol=r["protocol"],
                state=r["state"],
                service=r["service"],
                banner=r["banner"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # HTTP fingerprints
    # ------------------------------------------------------------------

    def save_fingerprints(self, session_id: int, results: List[HTTPFingerprint]) -> None:
        rows = [
            (
                session_id,
                r.url,
                r.status_code,
                r.server,
                r.content_type,
                r.x_powered_by,
                json.dumps(r.technologies),
                json.dumps(r.headers),
                r.redirect_url,
                r.response_time_ms,
                r.fingerprinted_at.isoformat(),
            )
            for r in results
        ]
        with self._conn:
            self._conn.executemany(
                """INSERT INTO http_fingerprints
                   (session_id, url, status_code, server, content_type, x_powered_by,
                    technologies, headers, redirect_url, response_time_ms, fingerprinted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )

    def get_fingerprints(self, session_id: int) -> List[HTTPFingerprint]:
        rows = self._conn.execute(
            "SELECT * FROM http_fingerprints WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        return [
            HTTPFingerprint(
                url=r["url"],
                status_code=r["status_code"],
                server=r["server"],
                content_type=r["content_type"],
                x_powered_by=r["x_powered_by"],
                technologies=json.loads(r["technologies"] or "[]"),
                headers=json.loads(r["headers"] or "{}"),
                redirect_url=r["redirect_url"],
                response_time_ms=r["response_time_ms"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Full session retrieval
    # ------------------------------------------------------------------

    def load_full_session(self, session_id: int) -> Optional[ScanSession]:
        """
        Reconstruct a ScanSession from the database including all child records.
        Returns None if the session_id does not exist.
        """
        row = self._conn.execute(
            "SELECT * FROM scan_sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None

        session = ScanSession(
            target=row["target"],
            started_at=datetime.datetime.fromisoformat(row["started_at"]),
            finished_at=(
                datetime.datetime.fromisoformat(row["finished_at"])
                if row["finished_at"]
                else None
            ),
            notes=row["notes"],
            subdomains=self.get_subdomains(session_id),
            ports=self.get_ports(session_id),
            http_fingerprints=self.get_fingerprints(session_id),
        )
        return session
