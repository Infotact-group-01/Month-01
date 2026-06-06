"""Tests for src.fetch_feeds — IOC classification & feed parsing."""

import pytest
import requests
from unittest.mock import patch, MagicMock

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


# ── AbuseIPDB (mocked HTTP) ───────────────────────────────────────────────────

class TestFetchAbuseIPDB:
    """Tests for fetch_abuseipdb() — all HTTP calls are mocked."""

    def test_returns_empty_without_api_key(self):
        """If ABUSEIPDB_API_KEY is empty, return [] immediately without an HTTP call."""
        with patch("src.fetch_feeds.ABUSEIPDB_API_KEY", ""):
            from src.fetch_feeds import fetch_abuseipdb
            result = fetch_abuseipdb()
            assert result == []

    def test_returns_correct_indicator_fields(self):
        """Verify the returned dict has the expected keys and values."""
        mock_data = {
            "data": [{
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 95,
                "countryCode": "US",
                "isp": "Example ISP",
                "totalReports": 10,
                "lastReportedAt": "2026-05-25T10:00:00+00:00",
                "categories": [18, 22],
            }]
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status = MagicMock()

        with patch("src.fetch_feeds.ABUSEIPDB_API_KEY", "fake-key"), \
             patch("requests.get", return_value=mock_resp):
            from src.fetch_feeds import fetch_abuseipdb
            result = fetch_abuseipdb(limit=1)

        assert len(result) == 1
        assert result[0]["indicator"] == "1.2.3.4"
        assert result[0]["type"] == "ip"
        assert result[0]["source"] == "AbuseIPDB"
        assert result[0]["confidence"] == 95

    def test_category_ids_mapped_to_tag_strings(self):
        """Category IDs 18 and 22 should map to 'brute-force' and 'ssh-brute-force'."""
        mock_data = {
            "data": [{
                "ipAddress": "5.5.5.5",
                "abuseConfidenceScore": 90,
                "countryCode": "DE",
                "isp": "",
                "totalReports": 5,
                "lastReportedAt": "2026-05-25T10:00:00+00:00",
                "categories": [18, 22],
            }]
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status = MagicMock()

        with patch("src.fetch_feeds.ABUSEIPDB_API_KEY", "fake-key"), \
             patch("requests.get", return_value=mock_resp):
            from src.fetch_feeds import fetch_abuseipdb
            result = fetch_abuseipdb()

        assert "brute-force" in result[0]["tags"]
        assert "ssh-brute-force" in result[0]["tags"]

    def test_returns_empty_on_http_error(self):
        """An HTTP error (e.g. 403 invalid key) should return [] gracefully."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError("403 Forbidden")
        mock_resp.text = "Forbidden"

        with patch("src.fetch_feeds.ABUSEIPDB_API_KEY", "bad-key"), \
             patch("requests.get", return_value=mock_resp):
            from src.fetch_feeds import fetch_abuseipdb
            result = fetch_abuseipdb()

        assert result == []


# ── AlienVault OTX (mocked HTTP) ─────────────────────────────────────────────

class TestFetchOTX:
    """Tests for fetch_otx() — all HTTP calls are mocked."""

    def test_returns_empty_without_api_key(self):
        """If OTX_API_KEY is empty, return [] immediately without an HTTP call."""
        with patch("src.fetch_feeds.OTX_API_KEY", ""):
            from src.fetch_feeds import fetch_otx
            result = fetch_otx()
            assert result == []

    def test_returns_all_supported_indicator_types(self):
        """A pulse with IPv4, domain, URL, and SHA256 should produce 4 indicators."""
        mock_data = {
            "results": [{
                "name": "TestPulse",
                "tags": ["ransomware"],
                "created": "2026-05-01T00:00:00Z",
                "indicators": [
                    {"type": "IPv4",            "indicator": "10.0.0.1",      "description": "C2"},
                    {"type": "domain",          "indicator": "evil.com",       "description": ""},
                    {"type": "URL",             "indicator": "http://evil.com/x", "description": ""},
                    {"type": "FileHash-SHA256", "indicator": "a" * 64,         "description": ""},
                ],
            }],
            "next": None,
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status = MagicMock()

        with patch("src.fetch_feeds.OTX_API_KEY", "fake-key"), \
             patch("requests.get", return_value=mock_resp):
            from src.fetch_feeds import fetch_otx
            result = fetch_otx(max_pulses=1)

        assert len(result) == 4
        types = {r["type"] for r in result}
        assert types == {"ip", "domain", "url", "hash"}

    def test_source_is_alienvault(self):
        """All returned indicators must have source='AlienVault'."""
        mock_data = {
            "results": [{"name": "P", "tags": [], "created": "2026-05-01T00:00:00Z",
                         "indicators": [{"type": "IPv4", "indicator": "1.1.1.1", "description": ""}]}],
            "next": None,
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status = MagicMock()

        with patch("src.fetch_feeds.OTX_API_KEY", "fake-key"), \
             patch("requests.get", return_value=mock_resp):
            from src.fetch_feeds import fetch_otx
            result = fetch_otx()

        assert all(r["source"] == "AlienVault" for r in result)

    def test_skips_unsupported_types(self):
        """Email and YARA indicator types should be silently skipped."""
        mock_data = {
            "results": [{"name": "P", "tags": [], "created": "2026-05-01T00:00:00Z",
                         "indicators": [
                             {"type": "email", "indicator": "evil@evil.com", "description": ""},
                             {"type": "IPv4",  "indicator": "9.9.9.9",       "description": ""},
                         ]}],
            "next": None,
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_data
        mock_resp.raise_for_status = MagicMock()

        with patch("src.fetch_feeds.OTX_API_KEY", "fake-key"), \
             patch("requests.get", return_value=mock_resp):
            from src.fetch_feeds import fetch_otx
            result = fetch_otx()

        assert len(result) == 1
        assert result[0]["indicator"] == "9.9.9.9"

    def test_returns_empty_on_http_error(self):
        """An HTTP error (e.g. 401 bad key) should return [] gracefully."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized")

        with patch("src.fetch_feeds.OTX_API_KEY", "bad-key"), \
             patch("requests.get", return_value=mock_resp):
            from src.fetch_feeds import fetch_otx
            result = fetch_otx()

        assert result == []
