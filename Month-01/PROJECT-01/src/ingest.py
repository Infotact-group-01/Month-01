"""Ingestion Orchestrator for TIP Project.
Fetches data from OSINT feeds, validates them, and inserts them into MongoDB.
"""

import logging
import datetime
from .fetch_feeds import fetch_all_feeds
from .models import Indicator
from .db import setup_database, insert_indicators

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

def process_feeds():
    """Main workflow to fetch, validate, and store OSINT indicators."""
    logger.info("Starting TIP ingestion process...")

    # 1. Ensure DB is set up with indices
    setup_database()

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
            # Validate indicator
            indicator_model = Indicator(**raw)
            valid_indicators.append(indicator_model.model_dump())
        except Exception as e:
            # Depending on how strict we want to be, we could log every validation error
            # For now, we skip bad indicators silently or with debug
            logger.debug(f"Validation failed for {raw.get('indicator')}: {e}")

    logger.info(f"Successfully validated {len(valid_indicators)} out of {len(raw_indicators)} indicators.")

    # 4. Insert into database
    if valid_indicators:
        inserted = insert_indicators(valid_indicators)
        logger.info(f"Ingestion complete. Inserted {inserted} new indicators into the database.")
    else:
        logger.warning("No valid indicators to insert.")

if __name__ == "__main__":
    process_feeds()
