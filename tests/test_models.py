"""
Tests for models/results.py

Validates Pydantic model constraints and field behaviour.
"""

import pytest
from pydantic import ValidationError

from models.results import HTTPFingerprint, PortResult, ScanSession, SubdomainResult


class TestPortResult:
    def test_valid_open_port(self):
        r = PortResult(port=443, state="open", service="https")
        assert r.port == 443
        assert r.state == "open"

    def test_valid_closed_port(self):
        r = PortResult(port=22, state="closed")
        assert r.state == "closed"

    def test_valid_filtered_port(self):
        r = PortResult(port=8080, state="filtered")
        assert r.state == "filtered"

    def test_port_below_range_raises(self):
        with pytest.raises(ValidationError):
            PortResult(port=0, state="open")

    def test_port_above_range_raises(self):
        with pytest.raises(ValidationError):
            PortResult(port=65536, state="open")

    def test_unknown_state_raises(self):
        with pytest.raises(ValidationError):
            PortResult(port=80, state="unknown")

    def test_default_protocol_is_tcp(self):
        r = PortResult(port=80, state="open")
        assert r.protocol == "tcp"


class TestSubdomainResult:
    def test_valid_subdomain(self):
        r = SubdomainResult(subdomain="api.example.com", source="crt.sh")
        assert r.subdomain == "api.example.com"

    def test_subdomain_lowercased(self):
        r = SubdomainResult(subdomain="  API.EXAMPLE.COM  ", source="crt.sh")
        assert r.subdomain == "api.example.com"

    def test_empty_subdomain_raises(self):
        with pytest.raises(ValidationError):
            SubdomainResult(subdomain="", source="crt.sh")

    def test_whitespace_only_subdomain_raises(self):
        with pytest.raises(ValidationError):
            SubdomainResult(subdomain="   ", source="crt.sh")

    def test_default_resolved_is_false(self):
        r = SubdomainResult(subdomain="a.example.com", source="crt.sh")
        assert r.resolved is False

    def test_resolved_with_ip(self):
        r = SubdomainResult(subdomain="a.example.com", source="crt.sh", resolved=True, ip_address="10.0.0.1")
        assert r.ip_address == "10.0.0.1"


class TestHTTPFingerprint:
    def test_minimal_fingerprint(self):
        fp = HTTPFingerprint(url="https://example.com")
        assert fp.url == "https://example.com"
        assert fp.technologies == []
        assert fp.headers == {}

    def test_full_fingerprint(self):
        fp = HTTPFingerprint(
            url="https://example.com",
            status_code=200,
            server="nginx",
            technologies=["Nginx", "PHP"],
            headers={"content-type": "text/html"},
            response_time_ms=98.4,
        )
        assert fp.status_code == 200
        assert "Nginx" in fp.technologies

    def test_technologies_defaults_to_empty_list(self):
        fp = HTTPFingerprint(url="https://example.com")
        assert fp.technologies == []


class TestScanSession:
    def test_default_empty_session(self):
        session = ScanSession(target="example.com")
        assert session.target == "example.com"
        assert session.subdomains == []
        assert session.ports == []
        assert session.http_fingerprints == []
        assert session.finished_at is None

    def test_mark_finished_sets_timestamp(self):
        session = ScanSession(target="example.com")
        assert session.finished_at is None
        session.mark_finished()
        assert session.finished_at is not None

    def test_duration_none_before_finished(self):
        session = ScanSession(target="example.com")
        assert session.duration_seconds is None

    def test_duration_positive_after_finished(self):
        import time
        session = ScanSession(target="example.com")
        time.sleep(0.01)
        session.mark_finished()
        assert session.duration_seconds is not None
        assert session.duration_seconds >= 0
