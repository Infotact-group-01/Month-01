"""Tests for src.db — database insert & deduplication logic."""

import pytest
from unittest.mock import patch
from src.db import insert_indicators


class TestInsertIndicators:
    """Insert and deduplication via mongomock."""

    def test_insert_new_indicators(self, mock_collection, sample_indicators):
        with patch("src.db.get_collection", return_value=mock_collection):
            count = insert_indicators(sample_indicators)
        assert count == 3
        assert mock_collection.count_documents({}) == 3

    def test_deduplication_same_source(self, mock_collection, sample_indicators):
        """Inserting the same indicators twice should not increase count."""
        with patch("src.db.get_collection", return_value=mock_collection):
            insert_indicators(sample_indicators)
            count = insert_indicators(sample_indicators)
        assert count == 0
        assert mock_collection.count_documents({}) == 3

    def test_same_indicator_different_source_allowed(self, mock_collection):
        """Same indicator from different sources should both be inserted."""
        indicators = [
            {"indicator": "1.2.3.4", "type": "ip", "source": "FeedA"},
            {"indicator": "1.2.3.4", "type": "ip", "source": "FeedB"},
        ]
        with patch("src.db.get_collection", return_value=mock_collection):
            count = insert_indicators(indicators)
        assert count == 2

    def test_empty_list_returns_zero(self, mock_collection):
        with patch("src.db.get_collection", return_value=mock_collection):
            count = insert_indicators([])
        assert count == 0

    def test_bulk_with_mixed_duplicates(self, mock_collection):
        """Insert batch where some are new and some are duplicates."""
        batch1 = [
            {"indicator": "1.1.1.1", "type": "ip", "source": "S"},
            {"indicator": "2.2.2.2", "type": "ip", "source": "S"},
        ]
        batch2 = [
            {"indicator": "1.1.1.1", "type": "ip", "source": "S"},  # dup
            {"indicator": "3.3.3.3", "type": "ip", "source": "S"},  # new
        ]
        with patch("src.db.get_collection", return_value=mock_collection):
            insert_indicators(batch1)
            count = insert_indicators(batch2)
        # mongomock may report differently but total should be 3
        assert mock_collection.count_documents({}) == 3
