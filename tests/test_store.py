"""
Tests for database/store.py

Uses an in-memory SQLite database to avoid filesystem side effects.
"""

import datetime
import tempfile
from pathlib import Path

import pytest

from database.store import ScanStore
from models.results import (
    HTTPFingerprint,
    PortResult,
    ScanSession,
    SubdomainResult,
)


@pytest.fixture()
def store(tmp_path: Path) -> ScanStore:
    """Provide a fresh ScanStore backed by a temporary file for each test."""
    db_path = tmp_path / "test_recon.db"
    return ScanStore(db_path=db_path)


class TestSessionManagement:
    def test_create_session_returns_integer_id(self, store: ScanStore):
        session = ScanSession(target="example.com")
        session_id = store.create_session(session)
        assert isinstance(session_id, int)
        assert session_id > 0

    def test_create_multiple_sessions_unique_ids(self, store: ScanStore):
        s1 = ScanSession(target="a.com")
        s2 = ScanSession(target="b.com")
        id1 = store.create_session(s1)
        id2 = store.create_session(s2)
        assert id1 != id2

    def test_get_session_by_target_returns_most_recent(self, store: ScanStore):
        s1 = ScanSession(target="example.com")
        s2 = ScanSession(target="example.com")
        id1 = store.create_session(s1)
        id2 = store.create_session(s2)
        row = store.get_session_by_target("example.com")
        assert row is not None
        assert row["id"] == id2

    def test_get_session_by_target_missing_returns_none(self, store: ScanStore):
        assert store.get_session_by_target("notexist.com") is None

    def test_finish_session_sets_timestamp(self, store: ScanStore):
        session = ScanSession(target="example.com")
        sid = store.create_session(session)
        ts = datetime.datetime(2024, 6, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        store.finish_session(sid, ts)
        row = store.get_session_by_target("example.com")
        assert row is not None
        assert "2024-06-01" in row["finished_at"]

    def test_list_sessions_returns_all(self, store: ScanStore):
        for name in ["a.com", "b.com", "c.com"]:
            store.create_session(ScanSession(target=name))
        sessions = store.list_sessions()
        assert len(sessions) == 3


class TestSubdomainStorage:
    def test_save_and_retrieve_subdomains(self, store: ScanStore):
        session = ScanSession(target="example.com")
        sid = store.create_session(session)

        results = [
            SubdomainResult(subdomain="a.example.com", source="crt.sh", resolved=True, ip_address="1.2.3.4"),
            SubdomainResult(subdomain="b.example.com", source="crt.sh", resolved=False),
        ]
        store.save_subdomains(sid, results)

        retrieved = store.get_subdomains(sid)
        assert len(retrieved) == 2
        names = {r.subdomain for r in retrieved}
        assert "a.example.com" in names
        assert "b.example.com" in names

    def test_resolved_flag_persisted_correctly(self, store: ScanStore):
        session = ScanSession(target="example.com")
        sid = store.create_session(session)

        results = [SubdomainResult(subdomain="resolved.example.com", source="crt.sh", resolved=True, ip_address="9.9.9.9")]
        store.save_subdomains(sid, results)

        retrieved = store.get_subdomains(sid)
        assert retrieved[0].resolved is True
        assert retrieved[0].ip_address == "9.9.9.9"

    def test_empty_subdomain_list_saves_cleanly(self, store: ScanStore):
        session = ScanSession(target="example.com")
        sid = store.create_session(session)
        store.save_subdomains(sid, [])
        assert store.get_subdomains(sid) == []


class TestPortStorage:
    def test_save_and_retrieve_ports(self, store: ScanStore):
        session = ScanSession(target="example.com")
        sid = store.create_session(session)

        results = [
            PortResult(port=80, state="open", service="http"),
            PortResult(port=443, state="open", service="https"),
            PortResult(port=22, state="filtered"),
        ]
        store.save_ports(sid, results)

        retrieved = store.get_ports(sid)
        assert len(retrieved) == 3
        states = {r.port: r.state for r in retrieved}
        assert states[80] == "open"
        assert states[22] == "filtered"


class TestFingerprintStorage:
    def test_save_and_retrieve_fingerprints(self, store: ScanStore):
        session = ScanSession(target="example.com")
        sid = store.create_session(session)

        results = [
            HTTPFingerprint(
                url="https://example.com",
                status_code=200,
                server="nginx",
                technologies=["Nginx", "Cloudflare"],
                headers={"content-type": "text/html"},
            )
        ]
        store.save_fingerprints(sid, results)

        retrieved = store.get_fingerprints(sid)
        assert len(retrieved) == 1
        fp = retrieved[0]
        assert fp.status_code == 200
        assert fp.server == "nginx"
        assert "Nginx" in fp.technologies


class TestFullSessionRoundtrip:
    def test_load_full_session_reconstructs_correctly(self, store: ScanStore):
        session = ScanSession(target="roundtrip.com")
        sid = store.create_session(session)

        store.save_subdomains(sid, [SubdomainResult(subdomain="www.roundtrip.com", source="crt.sh")])
        store.save_ports(sid, [PortResult(port=443, state="open", service="https")])
        store.save_fingerprints(sid, [HTTPFingerprint(url="https://roundtrip.com", status_code=301)])

        loaded = store.load_full_session(sid)
        assert loaded is not None
        assert loaded.target == "roundtrip.com"
        assert len(loaded.subdomains) == 1
        assert len(loaded.ports) == 1
        assert len(loaded.http_fingerprints) == 1

    def test_load_nonexistent_session_returns_none(self, store: ScanStore):
        assert store.load_full_session(99999) is None
