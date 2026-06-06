# models.py
"""Data models for TIP indicators.
We use Pydantic for validation and type safety. If Pydantic is not available, the script
falls back to a simple dataclass with manual validation.
"""

from __future__ import annotations

import datetime
from typing import Optional

try:
    from pydantic import BaseModel, Field, field_validator
except ImportError:  # pragma: no cover
    BaseModel = object  # type: ignore
    def field_validator(*args, **kwargs):
        def wrapper(fn):
            return fn
        return wrapper


class Indicator(BaseModel):
    """Canonical representation of a threat indicator.
    Fields:
        indicator (str): IP, domain, URL, or file hash.
        type (str): One of "ip", "domain", "url", "hash".
        source (str): Name of the OSINT feed.
        observed_at (datetime.datetime | None): When the indicator was first seen.
        confidence (int | None): Optional confidence score (0‑100).
        tags (list[str] | None): Optional tags for categorisation.
        risk_score (int | None): Calculated danger level (0‑100).
        first_seen (datetime.datetime | None): Timestamp of first ingestion (set once by DB).
        last_seen (datetime.datetime | None): Timestamp of most recent ingestion (updated by DB).
    """

    indicator: str = Field(..., min_length=1)
    type: str = Field(..., pattern="^(ip|domain|url|hash)$")
    source: str = Field(..., min_length=1)
    observed_at: Optional[datetime.datetime] = None
    confidence: Optional[int] = Field(85, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    # Lifecycle timestamps — populated/managed by the database layer (db.py)
    first_seen: Optional[datetime.datetime] = None
    last_seen: Optional[datetime.datetime] = None

    def calculate_risk(self) -> None:
        """Calculate a risk score based on real heuristics."""
        base_score = self.confidence if self.confidence is not None else 50

        # 1. Tag Severity
        tag_score = 0
        critical_tags = {"malware", "c2", "ransomware", "trojan", "botnet", "phishing"}
        high_tags = {"exploited", "attack", "compromised", "bruteforce"}
        medium_tags = {"scanner", "spam", "tor", "proxy", "vpn"}

        for t in self.tags:
            tag = t.lower()
            if tag in critical_tags:
                tag_score += 30
            elif tag in high_tags:
                tag_score += 20
            elif tag in medium_tags:
                tag_score += 10
            else:
                tag_score += 5

        # 2. Source Reliability
        source_weights = {"AbuseIPDB": 15, "VirusTotal": 10, "AlienVault": 5}
        source_score = source_weights.get(self.source, 0)

        # 3. Indicator Type Modifier
        type_score = 0
        if self.type == "hash":
            type_score = 10
        elif self.type in ("domain", "url"):
            type_score = 5

        # 4. Time Decay (Aging)
        decay = 0
        if self.observed_at:
            now = datetime.datetime.now(datetime.timezone.utc)
            days_old = (now - self.observed_at).days
            if days_old > 90:
                decay = 50
            elif days_old > 30:
                decay = 25
            elif days_old > 7:
                decay = 10

        raw_score = base_score + tag_score + source_score + type_score - decay
        self.risk_score = max(0, min(raw_score, 100))

    @field_validator("indicator")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()



# Fallback simple dataclass if Pydantic is unavailable
if BaseModel is object:  # pragma: no cover
    from dataclasses import dataclass, field

    @dataclass
    class Indicator:
        indicator: str
        type: str
        source: str
        observed_at: Optional[datetime.datetime] = None
        confidence: int = 85
        tags: list[str] = field(default_factory=list)
        risk_score: Optional[int] = None
        first_seen: Optional[datetime.datetime] = None
        last_seen: Optional[datetime.datetime] = None

        def calculate_risk(self) -> None:
            base_score = self.confidence if self.confidence is not None else 50
            tag_score = 0
            critical = {"malware", "c2", "ransomware", "trojan", "botnet", "phishing"}
            high = {"exploited", "attack", "compromised", "bruteforce"}
            medium = {"scanner", "spam", "tor", "proxy", "vpn"}

            for t in self.tags:
                tag = t.lower()
                if tag in critical: tag_score += 30
                elif tag in high: tag_score += 20
                elif tag in medium: tag_score += 10
                else: tag_score += 5

            source_score = {"AbuseIPDB": 15, "VirusTotal": 10, "AlienVault": 5}.get(self.source, 0)
            
            type_score = 10 if self.type == "hash" else (5 if self.type in ("domain", "url") else 0)

            decay = 0
            if self.observed_at:
                days_old = (datetime.datetime.now(datetime.timezone.utc) - self.observed_at).days
                if days_old > 90: decay = 50
                elif days_old > 30: decay = 25
                elif days_old > 7: decay = 10

            raw_score = base_score + tag_score + source_score + type_score - decay
            self.risk_score = max(0, min(raw_score, 100))
