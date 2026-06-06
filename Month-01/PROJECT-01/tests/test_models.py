"""Tests for src.models — Indicator Pydantic model."""

import datetime
import pytest
from src.models import Indicator


class TestIndicatorCreation:
    """Valid indicator construction."""

    def test_valid_ip_indicator(self):
        ind = Indicator(
            indicator="192.0.2.1",
            type="ip",
            source="TestFeed",
            observed_at=datetime.datetime.now(datetime.timezone.utc),
        )
        assert ind.indicator == "192.0.2.1"
        assert ind.type == "ip"
        assert ind.source == "TestFeed"

    def test_valid_domain_indicator(self):
        ind = Indicator(indicator="evil.org", type="domain", source="Feed2")
        assert ind.type == "domain"

    def test_valid_url_indicator(self):
        ind = Indicator(
            indicator="http://evil.org/payload", type="url", source="Feed3"
        )
        assert ind.type == "url"

    def test_valid_hash_indicator(self):
        ind = Indicator(
            indicator="d41d8cd98f00b204e9800998ecf8427e",
            type="hash",
            source="Feed4",
        )
        assert ind.type == "hash"


class TestIndicatorDefaults:
    """Default values and auto-population."""

    def test_default_confidence_is_85(self):
        ind = Indicator(indicator="1.2.3.4", type="ip", source="S")
        assert ind.confidence == 85

    def test_explicit_confidence_preserved(self):
        ind = Indicator(indicator="1.2.3.4", type="ip", source="S", confidence=50)
        assert ind.confidence == 50

    def test_tags_default_empty_list(self):
        """Tags should default to an empty list, never None."""
        ind = Indicator(indicator="1.2.3.4", type="ip", source="S")
        assert ind.tags == []
        assert isinstance(ind.tags, list)

    def test_lifecycle_timestamps_default_none(self):
        """first_seen and last_seen should be None before DB insertion."""
        ind = Indicator(indicator="1.2.3.4", type="ip", source="S")
        assert ind.first_seen is None
        assert ind.last_seen is None


class TestIndicatorValidation:
    """Rejection of bad data."""

    def test_reject_invalid_type(self):
        with pytest.raises(Exception):
            Indicator(indicator="1.2.3.4", type="unknown", source="S")

    def test_reject_empty_indicator(self):
        with pytest.raises(Exception):
            Indicator(indicator="", type="ip", source="S")

    def test_reject_empty_source(self):
        with pytest.raises(Exception):
            Indicator(indicator="1.2.3.4", type="ip", source="")

    def test_reject_confidence_over_100(self):
        with pytest.raises(Exception):
            Indicator(indicator="1.2.3.4", type="ip", source="S", confidence=150)

    def test_reject_confidence_below_0(self):
        with pytest.raises(Exception):
            Indicator(indicator="1.2.3.4", type="ip", source="S", confidence=-1)


class TestIndicatorStripping:
    """Whitespace handling."""

    def test_strips_leading_trailing_whitespace(self):
        ind = Indicator(indicator="  1.2.3.4  ", type="ip", source="S")
        assert ind.indicator == "1.2.3.4"


class TestRiskScoring:
    """Tests for the calculate_risk() method with the new heuristics engine.
    """

    def test_risk_score_is_none_before_calculate(self):
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed")
        assert ind.risk_score is None

    def test_risk_score_set_after_calculate(self):
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed")
        ind.calculate_risk()
        assert ind.risk_score is not None

    def test_testfeed_no_tags(self):
        """confidence=85, tags=0, source=0, type=0, decay=0 -> 85"""
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed", confidence=85)
        ind.calculate_risk()
        assert ind.risk_score == 85

    def test_tag_severity(self):
        """confidence=50, tags: malware=30, spam=10 -> 90"""
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed", confidence=50, tags=["malware", "spam"])
        ind.calculate_risk()
        assert ind.risk_score == 90

    def test_indicator_type_modifiers(self):
        """hash=+10, domain=+5, ip=0"""
        ind_hash = Indicator(indicator="d41d8cd98f00b204e9800998ecf8427e", type="hash", source="Test", confidence=50)
        ind_hash.calculate_risk()
        assert ind_hash.risk_score == 60  # 50 + 10

        ind_domain = Indicator(indicator="evil.com", type="domain", source="Test", confidence=50)
        ind_domain.calculate_risk()
        assert ind_domain.risk_score == 55  # 50 + 5

    def test_time_decay_over_90_days(self):
        """confidence=100. >90 days old -> -50 -> 50"""
        old_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=100)
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed", confidence=100, observed_at=old_date)
        ind.calculate_risk()
        assert ind.risk_score == 50

    def test_time_decay_over_30_days(self):
        """confidence=100. >30 days old -> -25 -> 75"""
        old_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed", confidence=100, observed_at=old_date)
        ind.calculate_risk()
        assert ind.risk_score == 75

    def test_time_decay_over_7_days(self):
        """confidence=100. >7 days old -> -10 -> 90"""
        old_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed", confidence=100, observed_at=old_date)
        ind.calculate_risk()
        assert ind.risk_score == 90

    def test_zero_confidence_low_score(self):
        """confidence=0, nothing else -> 0"""
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed", confidence=0)
        ind.calculate_risk()
        assert ind.risk_score == 0

    def test_abuseipdb_caps_at_100(self):
        """confidence=90 + malware(30) + abuseipdb(15) -> 135 -> caps at 100"""
        ind = Indicator(indicator="1.2.3.4", type="ip", source="AbuseIPDB", confidence=90, tags=["malware"])
        ind.calculate_risk()
        assert ind.risk_score == 100

    def test_multiple_calls_idempotent(self):
        """Calling calculate_risk() twice gives the same result."""
        ind = Indicator(indicator="1.2.3.4", type="ip", source="TestFeed")
        ind.calculate_risk()
        first = ind.risk_score
        ind.calculate_risk()
        assert ind.risk_score == first
