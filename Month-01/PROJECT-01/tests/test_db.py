"""Tests for src.db — database insert & deduplication logic."""

import pytest
from unittest.mock import patch, MagicMock
from src.db import insert_indicators
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError


class TestInsertIndicators:
    """Insert and deduplication logic tests using mocks."""

    def test_insert_new_indicators(self, sample_indicators):
        mock_col = MagicMock()
        mock_col.bulk_write.return_value = MagicMock(upserted_count=3, modified_count=0)
        
        with patch("src.db.get_collection", return_value=mock_col):
            count = insert_indicators(sample_indicators)
            
        assert count == 3
        mock_col.bulk_write.assert_called_once()
        ops = mock_col.bulk_write.call_args[0][0]
        assert len(ops) == 3
        assert isinstance(ops[0], UpdateOne)

    def test_empty_list_returns_zero(self):
        mock_col = MagicMock()
        with patch("src.db.get_collection", return_value=mock_col):
            count = insert_indicators([])
        assert count == 0
        mock_col.bulk_write.assert_not_called()

    def test_bulk_write_error_handled(self, sample_indicators):
        mock_col = MagicMock()
        # Simulate a partial success where 1 item was upserted before failure
        mock_col.bulk_write.side_effect = BulkWriteError({"nUpserted": 1})
        
        with patch("src.db.get_collection", return_value=mock_col):
            count = insert_indicators(sample_indicators)
            
        assert count == 1
        
    def test_unexpected_error_handled(self, sample_indicators):
        mock_col = MagicMock()
        mock_col.bulk_write.side_effect = Exception("DB Down")
        
        with patch("src.db.get_collection", return_value=mock_col):
            count = insert_indicators(sample_indicators)
            
        assert count == 0
