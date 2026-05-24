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

    def test_tags_default_none(self):
        ind = Indicator(indicator="1.2.3.4", type="ip", source="S")
        assert ind.tags is None


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
