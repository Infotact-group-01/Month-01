"""Elasticsearch client for TIP.

Compatible with elasticsearch-py v8/v9. Uses try/except for index existence
check to handle both 404 (index not found) and API differences across versions.
"""

import os
import logging
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, NotFoundError
from elasticsearch.helpers import bulk
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

ELASTICSEARCH_URI = os.getenv("ELASTICSEARCH_URI", "http://localhost:9200")
ES_USER           = os.getenv("ES_USER", "elastic")
ELASTIC_PASSWORD  = os.getenv("ELASTIC_PASSWORD", "")
INDEX_NAME = "indicators"

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
        }
    }
}


def get_es_client() -> Elasticsearch | None:
    """Return an authenticated Elasticsearch client, or None on failure."""
    try:
        kwargs = {"request_timeout": 10}
        if ELASTIC_PASSWORD:
            kwargs["basic_auth"] = (ES_USER, ELASTIC_PASSWORD)
        es = Elasticsearch(ELASTICSEARCH_URI, **kwargs)
        if not es.ping():
            logger.warning("Elasticsearch ping failed — SIEM sync disabled.")
            return None
        return es
    except Exception as e:
        logger.error(f"Cannot connect to Elasticsearch at {ELASTICSEARCH_URI}: {e}")
        return None


def setup_elasticsearch() -> None:
    """Ensure the indicators index exists with correct mappings."""
    es = get_es_client()
    if not es:
        return

    try:
        es.indices.get(index=INDEX_NAME)
        logger.info(f"Elasticsearch index '{INDEX_NAME}' already exists.")
    except NotFoundError:
        # Index doesn't exist — create it
        es.indices.create(index=INDEX_NAME, body=INDEX_MAPPINGS)
        logger.info(f"Created Elasticsearch index '{INDEX_NAME}'.")
    except Exception as e:
        logger.error(f"Failed to setup Elasticsearch index: {e}")


def index_indicators(indicators: list[dict]) -> int:
    """Bulk-upsert indicators into Elasticsearch. Returns count of indexed docs."""
    es = get_es_client()
    if not es or not indicators:
        return 0

    def _prep(ind: dict):
        # Strip MongoDB _id — not serializable and not needed in ES
        doc = {k: v for k, v in ind.items() if k != "_id"}
        # Serialize datetime to ISO string so Elasticsearch can parse it
        for k, v in doc.items():
            if isinstance(v, datetime):
                doc[k] = v.astimezone(timezone.utc).isoformat()
        return {
            "_index": INDEX_NAME,
            "_id": f"{doc.get('indicator')}::{doc.get('source')}",
            "_source": doc,
        }

    actions = [_prep(ind) for ind in indicators]

    try:
        success, failed = bulk(es, actions, raise_on_error=False)
        if failed:
            logger.warning(f"{len(failed)} indicators failed to index in Elasticsearch.")
        logger.info(f"Elasticsearch sync: {success} indexed, {len(failed)} failed.")
        return success
    except Exception as e:
        logger.error(f"Bulk index to Elasticsearch failed: {e}")
        return 0
