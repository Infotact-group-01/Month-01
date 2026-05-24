"""Database utilities for TIP project.
Handles MongoDB connections, index creation, and data insertion.
"""

import logging
from pymongo import MongoClient
from pymongo.errors import BulkWriteError, DuplicateKeyError
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

def insert_indicators(indicators: List[Dict[str, Any]]) -> int:
    """Insert a list of indicators into MongoDB, ignoring duplicates.
    
    Args:
        indicators: A list of indicator dictionaries.
        
    Returns:
        Number of successfully inserted indicators.
    """
    if not indicators:
        return 0
        
    collection = get_collection()
    inserted_count = 0
    
    # We use ordered=False to continue inserting even if duplicates are found
    try:
        result = collection.insert_many(indicators, ordered=False)
        inserted_count = len(result.inserted_ids)
    except BulkWriteError as e:
        # Filter out DuplicateKey errors to count actual inserted records
        inserted_count = e.details.get('nInserted', 0)
        duplicates = len(e.details.get('writeErrors', []))
        logger.info(f"Inserted {inserted_count} records. Skipped {duplicates} duplicates.")
    except Exception as e:
        logger.error(f"Error inserting indicators: {e}")
        
    return inserted_count
