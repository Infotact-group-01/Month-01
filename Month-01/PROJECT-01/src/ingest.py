"""Ingestion Orchestrator for TIP Project.
Fetches data from OSINT feeds, validates them, and inserts them into MongoDB.
"""

import logging
import datetime
from .fetch_feeds import fetch_all_feeds
from .models import Indicator
from .db import setup_database, insert_indicators
from .es_client import setup_elasticsearch, index_indicators

logger = logging.getLogger(__name__)

def process_feeds():
    """Main workflow to fetch, validate, and store OSINT indicators."""
    logger.info("Starting TIP ingestion process...")

    # 1. Ensure DB and ES are set up with indices
    setup_database()
    setup_elasticsearch()

    # 2. Fetch raw data from feeds
    raw_indicators = fetch_all_feeds()
    if not raw_indicators:
        logger.warning("No indicators fetched. Exiting.")
        return

    # 3. Validate and normalize data using Pydantic Models
    valid_indicators = []
    now = datetime.datetime.now(datetime.timezone.utc)

    for raw in raw_indicators:
        # Set observed_at to current time if missing
        if not raw.get("observed_at"):
            raw["observed_at"] = now

        try:
            # Validate indicator and calculate risk
            indicator_model = Indicator(**raw)
            indicator_model.calculate_risk()
            if hasattr(indicator_model, "model_dump"):
                valid_indicators.append(indicator_model.model_dump())
            else:
                import dataclasses
                valid_indicators.append(dataclasses.asdict(indicator_model))
        except Exception as e:
            # Depending on how strict we want to be, we could log every validation error
            # For now, we skip bad indicators silently or with debug
            logger.debug(f"Validation failed for {raw.get('indicator')}: {e}")

    logger.info(f"Successfully validated {len(valid_indicators)} out of {len(raw_indicators)} indicators.")

    # 4. Insert into database and Elasticsearch
    if valid_indicators:
        inserted = insert_indicators(valid_indicators)
        logger.info(f"Ingestion complete. Inserted {inserted} new indicators into the database.")
        es_inserted = index_indicators(valid_indicators)
        logger.info(f"Elasticsearch sync complete. Indexed {es_inserted} indicators.")
    else:
        logger.warning("No valid indicators to insert.")

if __name__ == "__main__":
    process_feeds()
