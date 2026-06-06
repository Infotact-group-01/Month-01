"""Shared utilities for TIP.

This module provides common helpers used across multiple modules to avoid
code duplication (e.g. the same IP validation regex appearing in both
fetch_feeds.py and rollback_api.py).
"""

from __future__ import annotations

import re
import socket

# ── IP validation ──────────────────────────────────────────────────────────────

#: Compiled regex that matches a valid IPv4 address in dotted-decimal notation.
IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

#: Compiled regex that matches MD5 / SHA-1 / SHA-256 / SHA-512 hashes (hex, 32–128 chars).
HASH_RE = re.compile(r"^[a-fA-F0-9]{32,128}$")


def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 address in dotted-decimal notation.

    Args:
        ip: String to validate.

    Returns:
        True if valid IPv4, False otherwise.

    Examples:
        >>> is_valid_ip("1.2.3.4")
        True
        >>> is_valid_ip("not-an-ip")
        False
        >>> is_valid_ip("999.0.0.1")
        False
    """
    return bool(IP_RE.match(ip))


def is_valid_ipv6(ip: str) -> bool:
    """Return True if *ip* is a valid IPv6 address.

    Uses Python's :mod:`socket` module for accurate validation, which handles
    all valid IPv6 forms including compressed notation (``::1``), full notation,
    and mixed IPv4-mapped addresses.

    Args:
        ip: String to validate.

    Returns:
        True if valid IPv6, False otherwise.

    Examples:
        >>> is_valid_ipv6("::1")
        True
        >>> is_valid_ipv6("2001:db8::1")
        True
        >>> is_valid_ipv6("fe80::1%eth0")
        False
        >>> is_valid_ipv6("not-an-ip")
        False
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, OSError, AttributeError):
        return False


def is_valid_any_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 **or** IPv6 address.

    Convenience wrapper that combines :func:`is_valid_ip` and
    :func:`is_valid_ipv6`.  Use this wherever the system should accept
    both address families (e.g. API input validation).

    Args:
        ip: String to validate.

    Returns:
        True if valid IPv4 or IPv6, False otherwise.

    Examples:
        >>> is_valid_any_ip("1.2.3.4")
        True
        >>> is_valid_any_ip("::1")
        True
        >>> is_valid_any_ip("2001:db8::dead:beef")
        True
        >>> is_valid_any_ip("not-an-ip")
        False
    """
    return is_valid_ip(ip) or is_valid_ipv6(ip)


def classify_ioc(value: str) -> str:
    """Classify an IOC string as ``ip``, ``domain``, ``url``, or ``hash``.

    Classification order (first match wins):
      1. URL    — starts with ``http://`` or ``https://``
      2. IPv4   — matches IPv4 dotted-decimal via :data:`IP_RE`
      3. IPv6   — validated via :func:`is_valid_ipv6`
      4. Hash   — 32–128 contiguous hex characters (MD5 / SHA-1 / SHA-256 / SHA-512)
      5. Domain — contains at least one dot
      6. Fallback — treated as ``ip`` (e.g. bare hostnames without a dot)

    Args:
        value: The raw IOC string to classify.

    Returns:
        One of ``"ip"``, ``"domain"``, ``"url"``, or ``"hash"``.

    Examples:
        >>> classify_ioc("1.2.3.4")
        'ip'
        >>> classify_ioc("2001:db8::1")
        'ip'
        >>> classify_ioc("http://evil.com/payload")
        'url'
        >>> classify_ioc("d41d8cd98f00b204e9800998ecf8427e")
        'hash'
        >>> classify_ioc("evil.example.com")
        'domain'
    """
    if value.startswith(("http://", "https://")):
        return "url"
    if IP_RE.match(value):
        return "ip"
    if is_valid_ipv6(value):
        return "ip"
    if HASH_RE.match(value):
        return "hash"
    if "." in value:
        return "domain"
    return "ip"
