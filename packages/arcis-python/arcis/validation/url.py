"""
Arcis SSRF (Server-Side Request Forgery) prevention.

Validates URLs to ensure they don't target private/internal networks,
localhost, cloud metadata endpoints, or use dangerous protocols.

Example:
    from arcis import validate_url_ssrf, is_url_safe

    result = validate_url_ssrf("http://169.254.169.254/latest/meta-data/")
    # ValidateUrlResult(safe=False, reason='link-local address (169.254.0.0/16)')

    if is_url_safe(user_provided_url):
        response = requests.get(user_provided_url)
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse


@dataclass
class ValidateUrlOptions:
    """Options for URL validation."""

    allowed_protocols: List[str] = field(default_factory=lambda: ["http", "https"])
    """Allowed protocols (without colon). Default: ['http', 'https']"""

    blocked_hosts: List[str] = field(default_factory=list)
    """Additional hostnames to block (e.g., internal service names)."""

    allowed_hosts: List[str] = field(default_factory=list)
    """Additional hostnames to always allow (bypass IP checks)."""

    allow_localhost: bool = False
    """Allow localhost/loopback. Default: False"""

    allow_private: bool = False
    """Allow private/internal IPs. Default: False"""


@dataclass
class ValidateUrlResult:
    """Result of URL validation."""

    safe: bool
    """Whether the URL is safe to fetch."""

    reason: Optional[str] = None
    """Reason the URL was blocked (only set when safe=False)."""


# Compiled regex patterns for IP checks
_RE_LOOPBACK = re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_10 = re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_172 = re.compile(r"^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$")
_RE_192 = re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$")
_RE_LINK_LOCAL = re.compile(r"^169\.254\.\d{1,3}\.\d{1,3}$")
_RE_CURRENT_NET = re.compile(r"^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _check_private_ip(hostname: str) -> Optional[str]:
    """Check if a hostname is a private/internal IP. Returns reason or None."""
    # 10.0.0.0/8
    if _RE_10.match(hostname):
        return "private address (10.0.0.0/8)"

    # 172.16.0.0/12
    m = _RE_172.match(hostname)
    if m:
        second = int(m.group(1))
        if 16 <= second <= 31:
            return "private address (172.16.0.0/12)"

    # 192.168.0.0/16
    if _RE_192.match(hostname):
        return "private address (192.168.0.0/16)"

    # 169.254.0.0/16 — link-local, includes cloud metadata
    if _RE_LINK_LOCAL.match(hostname):
        return "link-local address (169.254.0.0/16)"

    # 0.0.0.0/8 (current network)
    if _RE_CURRENT_NET.match(hostname):
        return "current network address (0.0.0.0/8)"

    # Cloud metadata hostnames
    if hostname in ("metadata.google.internal", "metadata.internal"):
        return "cloud metadata endpoint"

    # IPv6 private ranges
    ipv6 = hostname.strip("[]")
    if ipv6 in ("::1", "::"):
        return "private IPv6 address"
    if ipv6.startswith(("fc", "fd", "fe80")):
        return "private IPv6 address"

    return None


def validate_url_ssrf(
    url: str,
    options: Optional[ValidateUrlOptions] = None,
) -> ValidateUrlResult:
    """
    Validate a URL for SSRF safety.

    Checks:
    1. Valid URL format
    2. Allowed protocol (default: http, https only)
    3. Not localhost/loopback (127.x.x.x, ::1, localhost)
    4. Not private IP (10.x, 172.16-31.x, 192.168.x)
    5. Not link-local (169.254.x.x — includes cloud metadata endpoints)
    6. Not blocked hostname
    7. No credentials in URL (user:pass@host)

    Args:
        url: The URL string to validate.
        options: Validation options. Uses safe defaults if None.

    Returns:
        ValidateUrlResult with safe flag and optional reason.
    """
    if options is None:
        options = ValidateUrlOptions()

    if not isinstance(url, str) or url.strip() == "":
        return ValidateUrlResult(safe=False, reason="invalid URL: empty or not a string")

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        return ValidateUrlResult(safe=False, reason="invalid URL: failed to parse")

    # Must have scheme and netloc
    if not parsed.scheme or not parsed.netloc:
        return ValidateUrlResult(safe=False, reason="invalid URL: failed to parse")

    # Check protocol
    if parsed.scheme not in options.allowed_protocols:
        return ValidateUrlResult(
            safe=False,
            reason=f"disallowed protocol: {parsed.scheme}:",
        )

    # Check for credentials
    if parsed.username or parsed.password:
        return ValidateUrlResult(safe=False, reason="URL contains credentials")

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    # Check explicit allowlist (bypasses IP checks)
    if any(hostname == h.lower() for h in options.allowed_hosts):
        return ValidateUrlResult(safe=True)

    # Check explicit blocklist
    if any(hostname == h.lower() for h in options.blocked_hosts):
        return ValidateUrlResult(safe=False, reason=f"blocked host: {hostname}")

    # Check localhost/loopback
    if not options.allow_localhost:
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return ValidateUrlResult(safe=False, reason="loopback address")
        if hostname.endswith(".localhost"):
            return ValidateUrlResult(safe=False, reason="loopback address")
        if _RE_LOOPBACK.match(hostname):
            return ValidateUrlResult(safe=False, reason="loopback address")

    # Check private IPs
    if not options.allow_private:
        private_reason = _check_private_ip(hostname)
        if private_reason:
            return ValidateUrlResult(safe=False, reason=private_reason)

    return ValidateUrlResult(safe=True)


def is_url_safe(
    url: str,
    options: Optional[ValidateUrlOptions] = None,
) -> bool:
    """
    Convenience wrapper that returns True/False.

    Args:
        url: The URL to check.
        options: Validation options.

    Returns:
        True if the URL is safe to fetch.
    """
    return validate_url_ssrf(url, options).safe
