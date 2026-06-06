"""
load_demo_data.py
-----------------
Loads the curated demo dataset (data/demo_dataset.json) directly into
Elasticsearch for presentation/demo purposes.

Usage:
    python load_demo_data.py

Requirements:
  - Elasticsearch running on localhost:9200  (docker-compose up -d)
  - pip install elasticsearch python-dotenv
"""

import json
import os
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta

from dotenv import load_dotenv

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("demo-loader")

# ── Config ────────────────────────────────────────────────────────────────────
load_dotenv()
ELASTICSEARCH_URI = os.getenv("ELASTICSEARCH_URI", "http://localhost:9200")
INDEX_NAME = "indicators"
DATASET_PATH = Path(__file__).parent / "data" / "demo_dataset.json"

# Extended index mappings — includes extra demo fields (campaign, country, asn, description)
INDEX_MAPPINGS = {
    "mappings": {
        "properties": {
            "indicator":   {"type": "keyword"},
            "type":        {"type": "keyword"},
            "source":      {"type": "keyword"},
            "observed_at": {"type": "date"},
            "confidence":  {"type": "integer"},
            "tags":        {"type": "keyword"},
            "risk_score":  {"type": "integer"},
            "campaign":    {"type": "keyword"},
            "country":     {"type": "keyword"},
            "asn":         {"type": "keyword"},
            "description": {"type": "text"},
        }
    }
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client():
    """Return a connected Elasticsearch client or exit."""
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(ELASTICSEARCH_URI, request_timeout=10)
        if not es.ping():
            logger.error("Cannot reach Elasticsearch at %s — is Docker running?", ELASTICSEARCH_URI)
            sys.exit(1)
        info = es.info()
        logger.info("Connected to Elasticsearch %s", info["version"]["number"])
        return es
    except ImportError:
        logger.error("elasticsearch package not found. Run: pip install elasticsearch")
        sys.exit(1)
    except Exception as e:
        logger.error("Connection failed: %s", e)
        sys.exit(1)


def ensure_index(es):
    """Create (or re-create) the indicators index with full demo mappings."""
    from elasticsearch import NotFoundError
    try:
        es.indices.get(index=INDEX_NAME)
        logger.info("Index '%s' already exists.", INDEX_NAME)
        choice = input("  → Delete and recreate it for a fresh demo load? [y/N]: ").strip().lower()
        if choice == "y":
            es.indices.delete(index=INDEX_NAME)
            logger.info("Deleted index '%s'.", INDEX_NAME)
        else:
            logger.info("Keeping existing index — demo records will be upserted.")
    except NotFoundError:
        pass

    try:
        es.indices.get(index=INDEX_NAME)
    except Exception:
        es.indices.create(index=INDEX_NAME, mappings=INDEX_MAPPINGS["mappings"])
        logger.info("Created index '%s' with full demo mappings.", INDEX_NAME)


def load_dataset() -> list:
    """Load the JSON demo dataset from disk."""
    if not DATASET_PATH.exists():
        logger.error("Dataset not found at: %s", DATASET_PATH)
        sys.exit(1)
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.info("Loaded %d demo indicators from %s", len(data), DATASET_PATH.name)
    return data


def _spread_timestamps(records: list) -> list:
    """
    Spread timestamps evenly over the last 30 days so that
    the Kibana timeline looks realistic and interesting.
    """
    now = datetime.now(timezone.utc)
    total = len(records)
    for i, rec in enumerate(records):
        # Spread backwards: first record = 30 days ago, last = now
        days_back = 30 - (i / max(total - 1, 1)) * 30
        ts = now - timedelta(days=days_back)
        rec["observed_at"] = ts.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return records


def bulk_load(es, records: list):
    """Bulk-index the demo records into Elasticsearch."""
    from elasticsearch.helpers import bulk

    def _actions():
        for rec in records:
            yield {
                "_index": INDEX_NAME,
                "_id": f"{rec['indicator']}::{rec['source']}",
                "_source": rec,
            }

    success, failed = bulk(es, _actions(), raise_on_error=False)
    return success, failed


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 60)
    print("  TIP Demo Data Loader")
    print("  Loads realistic threat intelligence into Elasticsearch")
    print("=" * 60)
    print()

    es = get_client()
    ensure_index(es)
    records = load_dataset()
    records = _spread_timestamps(records)

    logger.info("Bulk-indexing %d records into '%s' ...", len(records), INDEX_NAME)
    success, failed = bulk_load(es, records)

    print()
    print("=" * 60)
    if failed:
        logger.warning("Indexed: %d  |  Failed: %d", success, len(failed))
        for f in failed[:5]:
            logger.warning("  Failed doc: %s", f)
    else:
        print(f"  ✅  Successfully indexed {success} demo indicators!")
        print()
        print("  Next steps:")
        print("  1. Open Kibana → http://localhost:5601")
        print("  2. Go to Stack Management → Index Patterns")
        print("  3. Create index pattern:  indicators  (time field: observed_at)")
        print("  4. Go to Discover → explore your data!")
        print()
        print("  Suggested filters for your demo:")
        print("  • risk_score: >90               → Critical threats only")
        print("  • type: ip                       → All malicious IPs")
        print("  • campaign: LockBit-3.0          → LockBit campaign IOCs")
        print("  • source: VirusTotal             → VirusTotal-sourced hashes")
        print("  • tags: ransomware AND c2        → Ransomware C2 infrastructure")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
