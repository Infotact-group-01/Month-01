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
    """

    indicator: str = Field(..., min_length=1)
    type: str = Field(..., pattern="^(ip|domain|url|hash)$")
    source: str = Field(..., min_length=1)
    observed_at: Optional[datetime.datetime] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    tags: Optional[list[str]] = None

    @field_validator("indicator")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()

    @field_validator("confidence")
    @classmethod
    def default_confidence(cls, v):
        return v if v is not None else 85



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
        tags: Optional[list[str]] = field(default_factory=list)
