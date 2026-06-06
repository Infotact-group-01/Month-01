import os
import json
import logging
from pathlib import Path
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

# ── Centralized logging setup ────────────────────────────────────────────────
def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging once for the entire application."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

setup_logging()
logger = logging.getLogger(__name__)

# Load .env from project root
BASE_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH)

# MongoDB settings
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("MONGODB_DB", "tip")
COLLECTION_NAME = os.getenv("MONGODB_COLLECTION", "indicators")

# Try to connect to real MongoDB, fallback to mongomock for testing if offline
try:
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2000)
    client.server_info() # Trigger immediate connection test
    logger.info("Connected to real MongoDB instance.")
except ServerSelectionTimeoutError:
    logger.warning("Real MongoDB not running! Falling back to 'mongomock' (in-memory database) for testing.")
    import mongomock
    client = mongomock.MongoClient(MONGODB_URI)

db = client[DB_NAME]
indicators = db[COLLECTION_NAME]

# Ensure unique index on (indicator, source)
indicators.create_index([("indicator", 1), ("source", 1)], unique=True, name="unique_indicator_source")

# Load feed URLs from feeds.json located at project root
FEEDS_PATH = BASE_DIR / "feeds.json"

def get_feed_urls():
    if not FEEDS_PATH.is_file():
        raise FileNotFoundError(f"feeds.json not found at {FEEDS_PATH}")
    with open(FEEDS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

FEED_URLS = get_feed_urls()

def get_db_collection():
    """Return the MongoDB collection for indicators."""
    return indicators


def validate_config() -> list[str]:
    """Check for missing optional configuration and return a list of warning strings.

    Call this at application startup to surface configuration gaps to the user.
    Returns an empty list if all optional keys are present.

    Returns:
        List of human-readable warning strings (empty = fully configured).
    """
    warnings: list[str] = []
    if not os.getenv("ABUSEIPDB_API_KEY"):
        warnings.append(
            "ABUSEIPDB_API_KEY not set — AbuseIPDB live feed will be skipped. "
            "Get a free key at https://www.abuseipdb.com/register"
        )
    if not os.getenv("OTX_API_KEY"):
        warnings.append(
            "OTX_API_KEY not set — AlienVault OTX feed will be skipped. "
            "Get a free key at https://otx.alienvault.com"
        )
    if not os.getenv("ELASTIC_PASSWORD"):
        warnings.append(
            "ELASTIC_PASSWORD not set — Elasticsearch authentication may fail. "
            "Set ELASTIC_PASSWORD in your .env file."
        )
    return warnings
