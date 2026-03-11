"""
Arcis Middleware - Security Headers

SecurityHeaders class for adding HTTP security headers to responses.
"""

from typing import Dict, Optional, Union

from ..core.constants import PATTERNS, HSTS_DEFAULT_MAX_AGE


class SecurityHeaders:
    """
    Security headers middleware component.

    Example:
        headers = SecurityHeaders(content_security_policy="default-src 'self'")
        headers.apply(response)
    """

    DEFAULT_HEADERS = PATTERNS.get("security_headers", {})

    def __init__(
        self,
        content_security_policy: Optional[str] = None,
        x_frame_options: str = "DENY",
        x_content_type_options: str = "nosniff",
        xss_filter: bool = True,
        hsts: bool = True,
        hsts_max_age: int = HSTS_DEFAULT_MAX_AGE,
        hsts_include_subdomains: bool = True,
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: str = "geolocation=(), microphone=(), camera=()",
        cache_control: Union[bool, str] = True,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        self.headers = dict(self.DEFAULT_HEADERS)

        if content_security_policy:
            self.headers["Content-Security-Policy"] = content_security_policy

        if x_frame_options:
            self.headers["X-Frame-Options"] = x_frame_options

        if x_content_type_options:
            self.headers["X-Content-Type-Options"] = x_content_type_options

        if xss_filter:
            self.headers["X-XSS-Protection"] = "1; mode=block"

        if hsts:
            hsts_value = f"max-age={hsts_max_age}"
            if hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            self.headers["Strict-Transport-Security"] = hsts_value

        if referrer_policy:
            self.headers["Referrer-Policy"] = referrer_policy

        if permissions_policy:
            self.headers["Permissions-Policy"] = permissions_policy

        # Cache-Control headers
        if cache_control:
            cache_control_value = (
                cache_control
                if isinstance(cache_control, str)
                else "no-store, no-cache, must-revalidate, proxy-revalidate"
            )
            self.headers["Cache-Control"] = cache_control_value
            self.headers["Pragma"] = "no-cache"
            self.headers["Expires"] = "0"

        self.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        if custom_headers:
            self.headers.update(custom_headers)

    def apply(self, response) -> None:
        """Apply security headers to a response object."""
        for header, value in self.headers.items():
            if hasattr(response, 'headers'):
                response.headers[header] = value
            elif hasattr(response, '__setitem__'):
                response[header] = value

    def get_headers(self) -> Dict[str, str]:
        """Get all security headers as a dict."""
        return dict(self.headers)
