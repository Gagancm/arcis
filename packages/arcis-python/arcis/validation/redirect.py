"""
Arcis Open Redirect prevention.

Prevents attackers from using your app to redirect users to malicious sites
via manipulated query parameters like ?returnUrl=http://evil.com

Example:
    from arcis import validate_redirect, is_redirect_safe

    result = validate_redirect("http://evil.com")
    # ValidateRedirectResult(safe=False, reason='absolute URL not in allowed hosts')

    if is_redirect_safe(user_url, allowed_hosts=["myapp.com"]):
        return redirect(user_url)
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse


@dataclass
class ValidateRedirectOptions:
    """Options for redirect validation."""

    allowed_hosts: List[str] = field(default_factory=list)
    """Hostnames that are allowed for absolute URL redirects."""

    allow_protocol_relative: bool = False
    """Allow protocol-relative URLs (//example.com). Default: False"""

    allowed_protocols: List[str] = field(default_factory=lambda: ["http", "https"])
    """Allowed protocols for absolute URLs (without colon). Default: ['http', 'https']"""


@dataclass
class ValidateRedirectResult:
    """Result of redirect validation."""

    safe: bool
    """Whether the redirect URL is safe."""

    reason: Optional[str] = None
    """Reason the redirect was blocked (only set when safe=False)."""


# Protocols that can execute code or exfiltrate data
_DANGEROUS_PROTOCOLS = re.compile(r"^(javascript|data|vbscript|blob):", re.IGNORECASE)

# Control characters used to disguise URLs
_CONTROL_CHARS = re.compile(r"[\t\n\r]")


def _extract_host(url: str) -> Optional[str]:
    """Extract hostname from a protocol-relative URL."""
    m = re.match(r"^//([^/:?#]+)", url)
    return m.group(1).lower() if m else None


def validate_redirect(
    url: str,
    options: Optional[ValidateRedirectOptions] = None,
) -> ValidateRedirectResult:
    """
    Validate a redirect URL to prevent open redirect attacks.

    Safe redirects:
    - Relative paths: /dashboard, /users?page=2, ../settings
    - Absolute URLs to allowed hosts (when configured)

    Blocked redirects:
    - Absolute URLs to unknown hosts
    - Protocol-relative URLs (//evil.com)
    - javascript:, data:, vbscript:, blob: protocols
    - Backslash-prefixed paths (\\\\evil.com — browser treats as //)
    - URLs with control characters that could disguise the target

    Args:
        url: The redirect target URL to validate.
        options: Validation options. Uses safe defaults if None.

    Returns:
        ValidateRedirectResult with safe flag and optional reason.
    """
    if options is None:
        options = ValidateRedirectOptions()

    if not isinstance(url, str) or url.strip() == "":
        return ValidateRedirectResult(
            safe=False, reason="invalid redirect: empty or not a string"
        )

    # Strip control characters that could disguise the URL
    cleaned = _CONTROL_CHARS.sub("", url)

    # Block dangerous protocols
    m = _DANGEROUS_PROTOCOLS.match(cleaned)
    if m:
        return ValidateRedirectResult(
            safe=False, reason=f"dangerous protocol: {m.group(0)}"
        )

    # Block backslash-prefixed paths — browsers treat \ as / in URLs
    if cleaned.startswith("\\"):
        return ValidateRedirectResult(
            safe=False,
            reason="backslash-prefixed URL (browser treats as protocol-relative)",
        )

    # Check protocol-relative URLs (//evil.com)
    if cleaned.startswith("//"):
        host = _extract_host(cleaned)
        if not options.allow_protocol_relative:
            # Still allow if host is in allowed list
            if host and any(host == h.lower() for h in options.allowed_hosts):
                return ValidateRedirectResult(safe=True)
            return ValidateRedirectResult(
                safe=False, reason="protocol-relative URL not in allowed hosts"
            )
        if host and options.allowed_hosts and not any(
            host == h.lower() for h in options.allowed_hosts
        ):
            return ValidateRedirectResult(
                safe=False, reason="protocol-relative URL not in allowed hosts"
            )
        return ValidateRedirectResult(safe=True)

    # Check if it's an absolute URL (has scheme)
    parsed = urlparse(cleaned)

    # urlparse will parse "http://evil.com" with scheme="http", netloc="evil.com"
    # but "/dashboard" with scheme="", netloc=""
    if not parsed.scheme or not parsed.netloc:
        # No scheme or no netloc — treat as relative path (safe)
        return ValidateRedirectResult(safe=True)

    # It's an absolute URL — check protocol
    if parsed.scheme not in options.allowed_protocols:
        return ValidateRedirectResult(
            safe=False, reason=f"disallowed protocol: {parsed.scheme}:"
        )

    # Check if host is in allowed list
    hostname = (parsed.hostname or "").lower()
    if not options.allowed_hosts:
        return ValidateRedirectResult(
            safe=False, reason="absolute URL not in allowed hosts"
        )

    if not any(hostname == h.lower() for h in options.allowed_hosts):
        return ValidateRedirectResult(
            safe=False, reason=f"host not allowed: {hostname}"
        )

    return ValidateRedirectResult(safe=True)


def is_redirect_safe(
    url: str,
    options: Optional[ValidateRedirectOptions] = None,
) -> bool:
    """
    Convenience wrapper that returns True/False.

    Args:
        url: The redirect URL to check.
        options: Validation options.

    Returns:
        True if the redirect is safe.
    """
    return validate_redirect(url, options).safe
