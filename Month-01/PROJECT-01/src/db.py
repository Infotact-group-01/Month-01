"""Database utilities for TIP project.
Handles MongoDB connections, index creation, and data insertion.

Deduplication strategy:
    Uses bulk ``UpdateOne`` upserts keyed on ``(indicator, source)``.
    - ``first_seen`` is set exactly once via ``$setOnInsert`` — never overwritten.
    - ``last_seen`` is updated on every re-ingestion via ``$set`` — tracks freshness.
    - All other fields (risk_score, tags, confidence) are also updated via ``$set``
      so re-running the pipeline keeps data current.
"""

import logging
from datetime import datetime, timezone
from pymongo import MongoClient, UpdateOne
from pymongo.errors import BulkWriteError
from typing import List, Dict, Any
from .config import MONGODB_URI, DB_NAME, COLLECTION_NAME

logger = logging.getLogger(__name__)

from .config import indicators


def get_collection():
    """Get MongoDB collection for indicators."""
    return indicators


def setup_database():
    """Ensure database collections and indices are properly configured."""
    collection = get_collection()
    # Create unique index to prevent duplicate indicators from the same source
    collection.create_index(
        [("indicator", 1), ("source", 1)],
        unique=True,
        name="unique_indicator_source"
    )
    logger.info("Database setup complete. Unique index on (indicator, source) is ready.")


def insert_indicators(records: List[Dict[str, Any]]) -> int:
    """Upsert a list of indicators into MongoDB with first_seen/last_seen tracking.

    Uses ``UpdateOne`` upserts rather than ``insert_many`` so that:
    - ``first_seen`` is set once on the very first insert and never changed.
    - ``last_seen`` is updated on every subsequent run to track data freshness.
    - All other fields (risk_score, tags, confidence) stay current with fresh data.

    Duplicate indicators (same ``indicator`` + ``source``) are updated, not
    re-inserted — so the unique index constraint is never violated.

    Args:
        records: A list of indicator dictionaries to upsert.

    Returns:
        Number of newly inserted records (updates to existing records are not counted).
    """
    if not records:
        return 0

    collection = get_collection()
    now = datetime.now(timezone.utc)

    ops = []
    for rec in records:
        observed_at = rec.get("observed_at") or now

        # Build the upsert operation:
        #   $setOnInsert  → fields written only on the very first insert
        #   $set          → fields written on every upsert (insert OR update)
        ops.append(UpdateOne(
            # Filter: unique key for deduplication
            {"indicator": rec["indicator"], "source": rec["source"]},
            {
                "$setOnInsert": {
                    "first_seen": observed_at,
                },
                "$set": {
                    "last_seen": observed_at,
                    # All indicator fields EXCEPT first_seen/last_seen
                    **{k: v for k, v in rec.items()
                       if k not in ("first_seen", "last_seen")},
                },
            },
            upsert=True,
        ))

    try:
        result = collection.bulk_write(ops, ordered=False)
        newly_inserted = result.upserted_count
        updated = result.modified_count
        if updated:
            logger.info(
                "Refreshed %d existing indicators with latest data.", updated
            )
        logger.info(
            "Inserted %d new indicators, updated %d existing.",
            newly_inserted, updated,
        )
        return newly_inserted
    except BulkWriteError as e:
        # Partial success — report what succeeded
        newly_inserted = e.details.get("nUpserted", 0)
        logger.warning(
            "Bulk write completed with errors. New inserts: %d. Error detail: %s",
            newly_inserted, e.details,
        )
        return newly_inserted
    except Exception as e:
        logger.error("Error during bulk upsert: %s", e)
        return 0
