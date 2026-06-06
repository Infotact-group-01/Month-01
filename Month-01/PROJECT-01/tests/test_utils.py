"""Tests for src.utils — shared IP validation and IOC classification utilities."""

import pytest
from src.utils import is_valid_ip, is_valid_ipv6, is_valid_any_ip, classify_ioc, IP_RE


# ── is_valid_ip ──────────────────────────────────────────────────────────────

class TestIsValidIP:
    """Verify is_valid_ip() accepts valid IPv4 and rejects everything else."""

    @pytest.mark.parametrize("ip", [
        "1.2.3.4",
        "0.0.0.0",
        "255.255.255.255",
        "192.168.0.1",
        "10.0.0.1",
        "172.16.254.254",
    ])
    def test_valid_ipv4_returns_true(self, ip):
        assert is_valid_ip(ip) is True

    @pytest.mark.parametrize("bad", [
        "not-an-ip",
        "256.0.0.1",        # octet > 255
        "1.2.3",            # too few octets
        "1.2.3.4.5",        # too many octets
        "evil.com",
        "http://1.2.3.4",   # has a prefix
        "",
        "::1",              # IPv6
    ])
    def test_invalid_values_return_false(self, bad):
        assert is_valid_ip(bad) is False


# ── is_valid_ipv6 ────────────────────────────────────────────────────────────

class TestIsValidIPv6:
    """Verify is_valid_ipv6() accepts valid IPv6 and rejects others."""

    @pytest.mark.parametrize("ip", [
        "::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
    ])
    def test_valid_ipv6_returns_true(self, ip):
        assert is_valid_ipv6(ip) is True

    @pytest.mark.parametrize("bad", [
        "1.2.3.4",          # IPv4 is not IPv6
        "not-an-ip",
        "2001:db8:::1",     # Too many colons
    ])
    def test_invalid_values_return_false(self, bad):
        assert is_valid_ipv6(bad) is False


# ── is_valid_any_ip ──────────────────────────────────────────────────────────

class TestIsValidAnyIP:
    """Verify is_valid_any_ip() accepts both IPv4 and IPv6."""

    @pytest.mark.parametrize("ip", [
        "1.2.3.4",
        "::1",
        "2001:db8::1",
    ])
    def test_valid_ips_return_true(self, ip):
        assert is_valid_any_ip(ip) is True

    @pytest.mark.parametrize("bad", [
        "not-an-ip",
        "evil.com",
        "256.0.0.1",
    ])
    def test_invalid_values_return_false(self, bad):
        assert is_valid_any_ip(bad) is False


# ── classify_ioc ─────────────────────────────────────────────────────────────

class TestClassifyIOC:
    """Verify classify_ioc() returns the correct type string."""

    def test_http_url(self):
        assert classify_ioc("http://evil.com/payload") == "url"

    def test_https_url(self):
        assert classify_ioc("https://phishing.org/login") == "url"

    def test_ipv4(self):
        assert classify_ioc("192.168.1.1") == "ip"

    def test_ipv6(self):
        assert classify_ioc("2001:db8::1") == "ip"

    def test_md5_hash(self):
        assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha256_hash(self):
        assert classify_ioc("a" * 64) == "hash"

    def test_domain(self):
        assert classify_ioc("evil.example.com") == "domain"

    def test_url_takes_priority_over_ip(self):
        """A URL containing an IP should still be classified as url."""
        assert classify_ioc("http://1.2.3.4/shell.php") == "url"

    def test_ip_takes_priority_over_hash(self):
        """An IPv4 address should not be classified as a hash even if it has hex chars."""
        assert classify_ioc("1.2.3.4") == "ip"

    def test_ipv6_takes_priority_over_hash(self):
        assert classify_ioc("2001:db8::1") == "ip"


# ── IP_RE regex ───────────────────────────────────────────────────────────────

class TestIPRegex:
    """Sanity-checks on the exported IP_RE compiled pattern."""

    def test_matches_standard_ip(self):
        assert IP_RE.match("10.20.30.40") is not None

    def test_does_not_match_domain(self):
        assert IP_RE.match("evil.com") is None
