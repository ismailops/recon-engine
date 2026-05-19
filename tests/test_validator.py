"""
Tests for core/validator.py

Covers: valid inputs, invalid inputs, edge cases, injection attempts.
"""

import pytest
from core.validator import parse_target
from models.target import TargetType


class TestValidDomains:
    def test_simple_domain(self):
        t = parse_target("example.com")
        assert t.hostname == "example.com"
        assert t.target_type == TargetType.DOMAIN

    def test_subdomain(self):
        t = parse_target("sub.example.com")
        assert t.hostname == "sub.example.com"

    def test_deeply_nested_subdomain(self):
        t = parse_target("a.b.c.example.com")
        assert t.hostname == "a.b.c.example.com"

    def test_domain_normalised_to_lowercase(self):
        t = parse_target("EXAMPLE.COM")
        assert t.hostname == "example.com"

    def test_domain_with_numbers(self):
        t = parse_target("example123.org")
        assert t.hostname == "example123.org"

    def test_domain_with_hyphen(self):
        t = parse_target("my-example.co.uk")
        assert t.hostname == "my-example.co.uk"


class TestValidIPs:
    def test_ipv4(self):
        t = parse_target("192.168.1.1")
        assert t.target_type == TargetType.IP
        assert t.hostname == "192.168.1.1"

    def test_ipv4_loopback(self):
        t = parse_target("127.0.0.1")
        assert t.hostname == "127.0.0.1"

    def test_ipv6(self):
        t = parse_target("2001:db8::1")
        assert t.target_type == TargetType.IP


class TestValidURLs:
    def test_http_url(self):
        t = parse_target("http://example.com")
        assert t.target_type == TargetType.URL
        assert t.scheme == "http"
        assert t.hostname == "example.com"

    def test_https_url(self):
        t = parse_target("https://example.com")
        assert t.scheme == "https"

    def test_url_with_port(self):
        t = parse_target("https://example.com:8443")
        assert t.port == 8443

    def test_url_with_path(self):
        t = parse_target("https://example.com/api/v1")
        assert t.path == "/api/v1"

    def test_url_hostname_lowercased(self):
        t = parse_target("https://EXAMPLE.COM")
        assert t.hostname == "example.com"


class TestInvalidInputs:
    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="empty"):
            parse_target("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty"):
            parse_target("   ")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="string"):
            parse_target(12345)  # type: ignore[arg-type]

    def test_too_long_target_raises(self):
        with pytest.raises(ValueError, match="length"):
            parse_target("a" * 254 + ".com")

    def test_plain_word_raises(self):
        with pytest.raises(ValueError):
            parse_target("notadomain")

    def test_path_only_raises(self):
        with pytest.raises(ValueError):
            parse_target("/etc/passwd")


class TestInjectionAttempts:
    """
    Ensure hostile inputs are rejected by the validator before
    reaching any scanner or subprocess.
    """

    def test_shell_semicolon_rejected(self):
        with pytest.raises(ValueError):
            parse_target("example.com;ls")

    def test_shell_pipe_rejected(self):
        with pytest.raises(ValueError):
            parse_target("example.com|whoami")

    def test_backtick_rejected(self):
        with pytest.raises(ValueError):
            parse_target("example.com`id`")

    def test_dollar_substitution_rejected(self):
        with pytest.raises(ValueError):
            parse_target("example.com$HOME")

    def test_newline_in_target_rejected(self):
        with pytest.raises(ValueError):
            parse_target("example.com\nmalicious")

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError):
            parse_target("example..com")

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError):
            parse_target("example\x00.com")
