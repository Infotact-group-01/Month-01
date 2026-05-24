"""Tests for src.fetch_feeds — IOC classification & feed parsing."""

import pytest
from src.fetch_feeds import _classify_ioc, parse_plain_iocs, _fetch_text


# ── IOC classification ───────────────────────────────────────────────────────

class TestClassifyIOC:
    """Verify _classify_ioc returns the correct type."""

    # IPs
    @pytest.mark.parametrize("ip", [
        "192.168.1.1", "10.0.0.1", "172.16.0.1", "255.255.255.255",
        "0.0.0.0", "192.0.2.45", "1.2.3.4",
    ])
    def test_ipv4_classified_as_ip(self, ip):
        """Regression: IPs were previously misclassified as 'domain'."""
        assert _classify_ioc(ip) == "ip"

    # Domains
    @pytest.mark.parametrize("domain", [
        "example.com", "malicious.net", "evil.org", "sub.domain.co.uk",
    ])
    def test_domain_classified_as_domain(self, domain):
        assert _classify_ioc(domain) == "domain"

    # URLs
    @pytest.mark.parametrize("url", [
        "http://badsite.com/malware",
        "https://evil.org/download",
        "http://10.0.0.1/path",
    ])
    def test_url_classified_as_url(self, url):
        assert _classify_ioc(url) == "url"

    # Hashes
    @pytest.mark.parametrize("hash_val", [
        "d41d8cd98f00b204e9800998ecf8427e",                         # MD5
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",                 # SHA-1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256
    ])
    def test_hash_classified_as_hash(self, hash_val):
        assert _classify_ioc(hash_val) == "hash"


# ── Feed parsing ─────────────────────────────────────────────────────────────

class TestParsePlainIOCs:
    """Verify parse_plain_iocs extracts and classifies IOCs."""

    def test_parses_mixed_feed(self):
        text = "192.168.1.1\nexample.com\nhttp://evil.org/payload\n"
        result = parse_plain_iocs(text, "Test")
        assert len(result) == 3
        types = [r["type"] for r in result]
        assert types == ["ip", "domain", "url"]

    def test_skips_blank_lines(self):
        text = "\n\n192.168.1.1\n\n\n"
        result = parse_plain_iocs(text, "Test")
        assert len(result) == 1

    def test_skips_comment_lines(self):
        text = "# this is a comment\n192.168.1.1\n# another comment\n"
        result = parse_plain_iocs(text, "Test")
        assert len(result) == 1
        assert result[0]["indicator"] == "192.168.1.1"

    def test_source_propagated(self):
        text = "1.2.3.4\n"
        result = parse_plain_iocs(text, "MySource")
        assert result[0]["source"] == "MySource"

    def test_observed_at_is_none(self):
        text = "1.2.3.4\n"
        result = parse_plain_iocs(text, "S")
        assert result[0]["observed_at"] is None


# ── File fetching ────────────────────────────────────────────────────────────

class TestFetchText:
    """Verify _fetch_text reads local files correctly."""

    def test_read_local_file(self, temp_feed_file):
        text = _fetch_text(f"file://{temp_feed_file}")
        assert "192.168.1.1" in text
        assert "example.com" in text

    def test_bad_url_returns_empty(self):
        text = _fetch_text("file://nonexistent_file_12345.txt")
        assert text == ""
