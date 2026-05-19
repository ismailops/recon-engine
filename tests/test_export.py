"""
Tests for utils/exporter.py and reports/markdown_report.py

All tests use temporary directories; no side effects on the working directory.
"""

import json
from pathlib import Path

import pytest

from models.results import HTTPFingerprint, PortResult, ScanSession, SubdomainResult
from reports.markdown_report import generate_markdown_report
from utils.exporter import export_session_json


@pytest.fixture()
def sample_session() -> ScanSession:
    session = ScanSession(target="example.com")
    session.subdomains = [
        SubdomainResult(subdomain="api.example.com", source="crt.sh", resolved=True, ip_address="1.2.3.4"),
        SubdomainResult(subdomain="mail.example.com", source="crt.sh", resolved=False),
    ]
    session.ports = [
        PortResult(port=80, state="open", service="http"),
        PortResult(port=443, state="open", service="https"),
        PortResult(port=8080, state="filtered"),
    ]
    session.http_fingerprints = [
        HTTPFingerprint(
            url="https://example.com",
            status_code=200,
            server="nginx/1.25.3",
            technologies=["Nginx", "Cloudflare"],
            response_time_ms=142.5,
        )
    ]
    session.mark_finished()
    return session


class TestJSONExport:
    def test_creates_json_file(self, tmp_path: Path, sample_session: ScanSession):
        path = export_session_json(sample_session, output_dir=tmp_path)
        assert path.exists()
        assert path.suffix == ".json"

    def test_json_is_valid(self, tmp_path: Path, sample_session: ScanSession):
        path = export_session_json(sample_session, output_dir=tmp_path)
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, dict)

    def test_json_contains_meta(self, tmp_path: Path, sample_session: ScanSession):
        path = export_session_json(sample_session, output_dir=tmp_path)
        data = json.loads(path.read_text())
        assert data["meta"]["target"] == "example.com"
        assert data["meta"]["tool"] == "recon-engine"

    def test_json_subdomains_count(self, tmp_path: Path, sample_session: ScanSession):
        path = export_session_json(sample_session, output_dir=tmp_path)
        data = json.loads(path.read_text())
        assert len(data["subdomains"]) == 2

    def test_json_ports_count(self, tmp_path: Path, sample_session: ScanSession):
        path = export_session_json(sample_session, output_dir=tmp_path)
        data = json.loads(path.read_text())
        assert len(data["ports"]) == 3

    def test_json_fingerprints_count(self, tmp_path: Path, sample_session: ScanSession):
        path = export_session_json(sample_session, output_dir=tmp_path)
        data = json.loads(path.read_text())
        assert len(data["http_fingerprints"]) == 1

    def test_duration_present_when_finished(self, tmp_path: Path, sample_session: ScanSession):
        path = export_session_json(sample_session, output_dir=tmp_path)
        data = json.loads(path.read_text())
        assert data["meta"]["duration_seconds"] is not None

    def test_output_directory_created_if_missing(self, tmp_path: Path, sample_session: ScanSession):
        nested = tmp_path / "deep" / "nested"
        path = export_session_json(sample_session, output_dir=nested)
        assert path.exists()


class TestMarkdownReport:
    def test_creates_markdown_file(self, tmp_path: Path, sample_session: ScanSession):
        path = generate_markdown_report(sample_session, output_dir=tmp_path)
        assert path.exists()
        assert path.suffix == ".md"

    def test_markdown_contains_target(self, tmp_path: Path, sample_session: ScanSession):
        path = generate_markdown_report(sample_session, output_dir=tmp_path)
        content = path.read_text()
        assert "example.com" in content

    def test_markdown_contains_subdomain(self, tmp_path: Path, sample_session: ScanSession):
        path = generate_markdown_report(sample_session, output_dir=tmp_path)
        content = path.read_text()
        assert "api.example.com" in content

    def test_markdown_contains_open_ports(self, tmp_path: Path, sample_session: ScanSession):
        path = generate_markdown_report(sample_session, output_dir=tmp_path)
        content = path.read_text()
        assert "443" in content
        assert "open" in content.lower()

    def test_markdown_contains_http_section(self, tmp_path: Path, sample_session: ScanSession):
        path = generate_markdown_report(sample_session, output_dir=tmp_path)
        content = path.read_text()
        assert "HTTP Fingerprints" in content
        assert "nginx" in content.lower()

    def test_markdown_contains_summary_table(self, tmp_path: Path, sample_session: ScanSession):
        path = generate_markdown_report(sample_session, output_dir=tmp_path)
        content = path.read_text()
        assert "Summary" in content

    def test_empty_session_does_not_crash(self, tmp_path: Path):
        empty_session = ScanSession(target="empty.com")
        empty_session.mark_finished()
        path = generate_markdown_report(empty_session, output_dir=tmp_path)
        assert path.exists()
        content = path.read_text()
        assert "empty.com" in content

    def test_disclaimer_present(self, tmp_path: Path, sample_session: ScanSession):
        path = generate_markdown_report(sample_session, output_dir=tmp_path)
        content = path.read_text()
        assert "authorized" in content.lower()
