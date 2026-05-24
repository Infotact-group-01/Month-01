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

import re
import logging
from typing import List, Dict
import requests
from .config import FEED_URLS

logger = logging.getLogger(__name__)

# ── IOC classification patterns ──────────────────────────────────────────────
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,128}$")


def _classify_ioc(value: str) -> str:
    """Classify an IOC string as ip, domain, url, or hash.

    Order of checks:
      1. URL  – starts with http:// or https://
      2. IP   – matches dotted-decimal IPv4
      3. Hash – 32-128 hex characters (MD5 / SHA-1 / SHA-256 / SHA-512)
      4. Domain – contains a dot
      5. Fallback – treat as ip (e.g. bare hostnames)
    """
    if value.startswith(("http://", "https://")):
        return "url"
    if _IP_RE.match(value):
        return "ip"
    if _HASH_RE.match(value):
        return "hash"
    if "." in value:
        return "domain"
    return "ip"


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
    walks the lines, classifies the indicator type using :func:`_classify_ioc`,
    and builds the canonical dictionary.  Comment lines (starting with ``#``)
    and blank lines are skipped.
    """
    iocs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ioc_type = _classify_ioc(line)
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
