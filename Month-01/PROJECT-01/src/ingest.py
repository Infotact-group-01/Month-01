import logging
import datetime
from .fetch_feeds import fetch_all_feeds
from .models import Indicator
from .db import setup_database, insert_indicators
from .es_client import setup_elasticsearch, index_indicators
from .config import validate_config

logger = logging.getLogger(__name__)

def process_feeds() -> dict:
    """Main workflow to fetch, validate, and store OSINT indicators.

    Returns:
        A summary dict with keys:
          - ``fetched``   (int): Raw indicators pulled from all feeds.
          - ``validated`` (int): Indicators that passed Pydantic validation.
          - ``inserted``  (int): New records inserted into MongoDB.
          - ``indexed``   (int): Records synced to Elasticsearch.
    """
    logger.info("Starting TIP ingestion process...")

    # Surface any missing API key configuration early
    for warning in validate_config():
        logger.warning("CONFIG: %s", warning)

    summary = {"fetched": 0, "validated": 0, "inserted": 0, "indexed": 0}

    # 1. Ensure DB and ES are set up with indices
    setup_database()
    setup_elasticsearch()

    # 2. Fetch raw data from feeds
    raw_indicators = fetch_all_feeds()
    summary["fetched"] = len(raw_indicators)
    if not raw_indicators:
        logger.warning("No indicators fetched. Exiting.")
        return summary

    # 3. Validate and normalize data using Pydantic models
    valid_indicators = []
    now = datetime.datetime.now(datetime.timezone.utc)

    for raw in raw_indicators:
        # Set observed_at to current time if missing
        if not raw.get("observed_at"):
            raw["observed_at"] = now

        try:
            indicator_model = Indicator(**raw)
            indicator_model.calculate_risk()
            if hasattr(indicator_model, "model_dump"):
                valid_indicators.append(indicator_model.model_dump())
            else:
                import dataclasses
                valid_indicators.append(dataclasses.asdict(indicator_model))
        except Exception as e:
            logger.debug("Validation failed for %s: %s", raw.get("indicator"), e)

    summary["validated"] = len(valid_indicators)
    logger.info(
        "Successfully validated %d out of %d indicators.",
        len(valid_indicators), len(raw_indicators),
    )

    # 4. Insert into database and Elasticsearch
    if valid_indicators:
        inserted = insert_indicators(valid_indicators)
        summary["inserted"] = inserted
        logger.info("Ingestion complete. Inserted %d new indicators into the database.", inserted)

        es_inserted = index_indicators(valid_indicators)
        summary["indexed"] = es_inserted
        logger.info("Elasticsearch sync complete. Indexed %d indicators.", es_inserted)
    else:
        logger.warning("No valid indicators to insert.")

    return summary


if __name__ == "__main__":
    process_feeds()
