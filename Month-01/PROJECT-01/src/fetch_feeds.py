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
import os
import logging
from typing import List, Dict
from datetime import datetime, timezone
import requests
from dotenv import load_dotenv
from .config import FEED_URLS
from .utils import classify_ioc

load_dotenv()
logger = logging.getLogger(__name__)

# ── AbuseIPDB API config ─────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"

# ── AlienVault OTX API config ────────────────────────────────────────────────
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Map OTX indicator types to TIP types
_OTX_TYPE_MAP = {
    "IPv4":            "ip",
    "IPv6":            "ip",
    "domain":          "domain",
    "hostname":        "domain",
    "URL":             "url",
    "FileHash-MD5":    "hash",
    "FileHash-SHA1":   "hash",
    "FileHash-SHA256": "hash",
}

# AbuseIPDB category names (https://www.abuseipdb.com/categories)
ABUSEIPDB_CATEGORIES = {
    1:  "dns-compromise",
    2:  "dns-poisoning",
    3:  "fraud-orders",
    4:  "ddos",
    5:  "ftp-brute-force",
    6:  "ping-of-death",
    7:  "phishing",
    8:  "fraud-voip",
    9:  "open-proxy",
    10: "web-spam",
    11: "email-spam",
    12: "blog-spam",
    13: "vpn-ip",
    14: "port-scan",
    15: "hacking",
    16: "sql-injection",
    17: "spoofing",
    18: "brute-force",
    19: "bad-web-bot",
    20: "exploited-host",
    21: "web-attack",
    22: "ssh-brute-force",
    23: "iot-targeted",
}

# ── IOC classification ───────────────────────────────────────────────────────
# Delegate to the shared utility so the logic lives in exactly one place.
# The private alias keeps backward compatibility with existing tests that
# import `_classify_ioc` directly from this module.
_classify_ioc = classify_ioc


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


def fetch_abuseipdb(limit: int = 500) -> List[Dict]:
    """Fetch the AbuseIPDB IP blacklist via their v2 API.

    Returns up to ``limit`` malicious IPs with confidence scores,
    country codes, and abuse category tags.

    Args:
        limit: Maximum number of IPs to fetch (default 500, max 10000 on paid plans).

    Returns:
        List of indicator dicts compatible with the TIP pipeline.
    """
    if not ABUSEIPDB_API_KEY:
        logger.warning("ABUSEIPDB_API_KEY not set — skipping AbuseIPDB feed.")
        return []

    logger.info("Fetching AbuseIPDB blacklist (limit=%d) ...", limit)

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "confidenceMinimum": 75,   # Only high-confidence entries
                "limit": limit,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.HTTPError as e:
        logger.error("AbuseIPDB API HTTP error: %s — %s", e, resp.text[:300])
        return []
    except Exception as e:
        logger.error("AbuseIPDB fetch failed: %s", e)
        return []

    records = data.get("data", [])
    iocs = []

    for entry in records:
        ip = entry.get("ipAddress", "").strip()
        if not ip:
            continue

        # Map numeric category IDs to human-readable tag strings
        category_ids = entry.get("categories", [])
        tags = [
            ABUSEIPDB_CATEGORIES[c]
            for c in category_ids
            if c in ABUSEIPDB_CATEGORIES
        ]

        # Use the AbuseIPDB confidence score directly (0–100)
        confidence = min(int(entry.get("abuseConfidenceScore", 85)), 100)

        # Parse the last reported timestamp
        last_reported = entry.get("lastReportedAt")
        if last_reported:
            try:
                observed_at = datetime.fromisoformat(
                    last_reported.replace("Z", "+00:00")
                )
            except ValueError:
                observed_at = datetime.now(timezone.utc)
        else:
            observed_at = datetime.now(timezone.utc)

        iocs.append({
            "indicator": ip,
            "type": "ip",
            "source": "AbuseIPDB",
            "observed_at": observed_at.isoformat(),
            "confidence": confidence,
            "tags": tags,
            "country": entry.get("countryCode", ""),
            "isp": entry.get("isp", ""),
            "total_reports": entry.get("totalReports", 0),
        })

    logger.info("AbuseIPDB: fetched %d live malicious IPs.", len(iocs))
    return iocs


def fetch_otx(max_pulses: int = 20) -> List[Dict]:
    """Fetch threat indicators from AlienVault OTX subscribed pulses.

    Connects to the OTX API using the configured API key, retrieves the
    most recently modified pulses, and extracts all supported indicator
    types (IP, domain, URL, file hash).

    Args:
        max_pulses: Maximum number of pulses to fetch (default 20).

    Returns:
        List of indicator dicts compatible with the TIP pipeline.
    """
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping AlienVault OTX feed.")
        return []

    logger.info("Fetching AlienVault OTX subscribed pulses (max=%d) ...", max_pulses)

    iocs = []
    page = 1
    fetched_pulses = 0

    while fetched_pulses < max_pulses:
        try:
            resp = requests.get(
                f"{OTX_BASE_URL}/pulses/subscribed",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                params={"limit": min(10, max_pulses - fetched_pulses), "page": page},
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.HTTPError as e:
            logger.error("OTX API HTTP error: %s", e)
            break
        except Exception as e:
            logger.error("OTX fetch failed: %s", e)
            break

        pulses = data.get("results", [])
        if not pulses:
            break

        for pulse in pulses:
            pulse_name = pulse.get("name", "OTX-Unknown")
            pulse_tags = pulse.get("tags", [])
            pulse_created = pulse.get("created", None)

            # Parse pulse timestamp
            if pulse_created:
                try:
                    observed_at = datetime.fromisoformat(
                        pulse_created.replace("Z", "+00:00")
                    ).isoformat()
                except ValueError:
                    observed_at = datetime.now(timezone.utc).isoformat()
            else:
                observed_at = datetime.now(timezone.utc).isoformat()

            for ind in pulse.get("indicators", []):
                raw_type = ind.get("type", "")
                tip_type = _OTX_TYPE_MAP.get(raw_type)
                if not tip_type:
                    continue  # Skip unsupported types (email, YARA, etc.)

                indicator_value = ind.get("indicator", "").strip()
                if not indicator_value:
                    continue

                # Combine pulse tags + indicator description as tags
                ind_desc = ind.get("description", "")
                combined_tags = list(pulse_tags)
                if ind_desc and ind_desc not in combined_tags:
                    combined_tags.append(ind_desc)

                iocs.append({
                    "indicator":   indicator_value,
                    "type":        tip_type,
                    "source":      "AlienVault",
                    "observed_at": observed_at,
                    "confidence":  80,
                    "tags":        combined_tags[:5],  # Cap at 5 tags
                    "campaign":    pulse_name,
                })

        fetched_pulses += len(pulses)

        # If no next page, stop
        if not data.get("next"):
            break
        page += 1

    logger.info("AlienVault OTX: fetched %d indicators from %d pulses.",
                len(iocs), fetched_pulses)
    return iocs


def fetch_all_feeds() -> List[Dict]:
    """Fetch every feed listed in :data:`config.FEED_URLS` plus live API feeds.

    Returns a flat list of indicator dictionaries.
    """
    all_iocs = []

    # ── Standard text-based feeds ────────────────────────────────────────────
    for source, url in FEED_URLS.items():
        logger.info("Fetching %s", source)
        raw = _fetch_text(url)
        iocs = parse_plain_iocs(raw, source)
        all_iocs.extend(iocs)

    # ── AbuseIPDB live API feed ───────────────────────────────────────────────
    abuseipdb_iocs = fetch_abuseipdb(limit=500)
    all_iocs.extend(abuseipdb_iocs)

    # ── AlienVault OTX live API feed ─────────────────────────────────────────
    otx_iocs = fetch_otx(max_pulses=20)
    all_iocs.extend(otx_iocs)

    logger.info("Fetched total %d indicators", len(all_iocs))
    return all_iocs

if __name__ == "__main__":
    import json
    fetched = fetch_all_feeds()
    print(json.dumps(fetched[:5], indent=2, default=str))
