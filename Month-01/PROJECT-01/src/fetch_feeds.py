# fetch_feeds.py
"""Fetch threat intelligence feeds.

This script retrieves raw indicator data from a list of OSINT feed URLs
specified in :pycode:`config.FEED_URLS`.  It returns a list of dictionaries
with the keys ``indicator``, ``type`` (ip/domain/url), ``source`` and
``observed_at``.

The function is deliberately lightweight – it only performs HTTP GET
requests and extracts simple text/JSON payloads.  More complex parsers can be
added later.
"""

import logging
from typing import List, Dict
import requests
from .config import FEED_URLS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _fetch_text(url: str) -> str:
    """Return the raw response body for a URL.

    Args:
        url: Feed URL (can be http/https or file://).
    Returns:
        The response body as a string.
    """
    try:
        # Handle local file:// URLs
        if url.startswith("file://"):
            filepath = url[7:]  # Remove "file://" prefix
            from pathlib import Path
            import sys
            # Resolve relative to project root
            if not Path(filepath).is_absolute():
                filepath = str(Path(__file__).resolve().parents[1] / filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()

        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        logger.error("Failed to fetch %s: %s", url, exc)
        return ""

def parse_plain_iocs(text: str, source: str) -> List[Dict]:
    """Parse a newline‑separated list of IOCs.

    The most common simple feeds provide one indicator per line.  This helper
    walks the lines, classifies the indicator type, and builds the canonical
    dictionary.
    """
    iocs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "/" in line:
            ioc_type = "url"
        elif ":" in line:
            ioc_type = "ip"
        else:
            # naive heuristic – treat as domain if it contains a dot
            ioc_type = "domain" if "." in line else "ip"
        iocs.append({
            "indicator": line,
            "type": ioc_type,
            "source": source,
            "observed_at": None,
        })
    return iocs

def fetch_all_feeds() -> List[Dict]:
    """Fetch every feed listed in :data:`config.FEED_URLS`.

    Returns a flat list of indicator dictionaries.
    """
    all_iocs = []
    for source, url in FEED_URLS.items():
        logger.info("Fetching %s", source)
        raw = _fetch_text(url)
        iocs = parse_plain_iocs(raw, source)
        all_iocs.extend(iocs)
    logger.info("Fetched total %d indicators", len(all_iocs))
    return all_iocs

if __name__ == "__main__":
    import json
    fetched = fetch_all_feeds()
    print(json.dumps(fetched, indent=2))
