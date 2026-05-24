"""Shared pytest fixtures for TIP tests."""

import datetime
import tempfile
from pathlib import Path

import mongomock
import pytest


@pytest.fixture()
def mock_collection():
    """Return a fresh mongomock collection with the unique index applied."""
    client = mongomock.MongoClient()
    col = client["tip_test"]["indicators"]
    col.create_index(
        [("indicator", 1), ("source", 1)],
        unique=True,
        name="unique_indicator_source",
    )
    yield col
    client.close()


@pytest.fixture()
def sample_indicators():
    """Return a small list of valid indicator dicts."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return [
        {
            "indicator": "192.0.2.1",
            "type": "ip",
            "source": "TestFeed",
            "observed_at": now,
            "confidence": 90,
            "tags": ["malware"],
        },
        {
            "indicator": "evil.org",
            "type": "domain",
            "source": "TestFeed",
            "observed_at": now,
            "confidence": 75,
            "tags": ["phishing"],
        },
        {
            "indicator": "http://badsite.com/malware",
            "type": "url",
            "source": "TestFeed",
            "observed_at": now,
            "confidence": 95,
            "tags": ["c2"],
        },
    ]


@pytest.fixture()
def temp_feed_file(tmp_path: Path):
    """Create a temporary text feed file and return its path."""
    content = (
        "192.168.1.1\n"
        "10.0.0.1\n"
        "example.com\n"
        "malicious.net\n"
        "http://evil.org/payload\n"
        "https://threat.com/file\n"
        "d41d8cd98f00b204e9800998ecf8427e\n"  # MD5 hash
    )
    feed_file = tmp_path / "test_feed.txt"
    feed_file.write_text(content, encoding="utf-8")
    return feed_file
