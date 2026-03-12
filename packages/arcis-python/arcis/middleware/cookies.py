"""
Arcis Middleware - Secure Cookie Defaults

Enforces HttpOnly, Secure, and SameSite on cookies.
Prevents XSS cookie theft and CSRF attacks.
"""

import os
from typing import Optional


def enforce_secure_cookie(
    cookie_str: str,
    http_only: bool = True,
    secure: bool = True,
    same_site: Optional[str] = "Lax",
    path: Optional[str] = None,
) -> str:
    """
    Enforce secure defaults on a Set-Cookie header value.

    Args:
        cookie_str: The original Set-Cookie header value
        http_only: Add HttpOnly flag (prevents JS access)
        secure: Add Secure flag (HTTPS only)
        same_site: SameSite value ('Strict', 'Lax', 'None', or None to skip)
        path: Override Path attribute (None to keep original)

    Returns:
        The cookie string with secure attributes enforced
    """
    lower = cookie_str.lower()
    result = cookie_str

    # HttpOnly — prevent JavaScript access
    if http_only and "httponly" not in lower:
        result += "; HttpOnly"

    # Secure — HTTPS only
    if secure and "; secure" not in lower:
        result += "; Secure"

    # SameSite — CSRF protection
    if same_site is not None and "samesite" not in lower:
        result += f"; SameSite={same_site}"
        # SameSite=None requires Secure
        if same_site == "None" and "; secure" not in result.lower():
            result += "; Secure"

    # Override path if specified
    if path is not None:
        import re
        if "path=" in lower:
            result = re.sub(r";\s*path=[^;]*", f"; Path={path}", result, flags=re.IGNORECASE)
        else:
            result += f"; Path={path}"

    return result


class SecureCookieDefaults:
    """
    Enforces secure cookie defaults.

    Args:
        http_only: Add HttpOnly to all cookies. Default: True
        secure: Add Secure to all cookies. Default: True in production
        same_site: SameSite attribute. Default: 'Lax'
        path: Override Path attribute. Default: None

    Example:
        cookie_enforcer = SecureCookieDefaults()
        secured = cookie_enforcer.enforce("session=abc123")
        # "session=abc123; HttpOnly; Secure; SameSite=Lax"
    """

    def __init__(
        self,
        http_only: bool = True,
        secure: Optional[bool] = None,
        same_site: Optional[str] = "Lax",
        path: Optional[str] = None,
    ):
        self.http_only = http_only
        self.secure = secure if secure is not None else (
            os.environ.get("FLASK_ENV") != "development"
            and os.environ.get("FLASK_DEBUG") != "1"
        )
        self.same_site = same_site
        self.path = path

    def enforce(self, cookie_str: str) -> str:
        """Enforce secure defaults on a Set-Cookie header value."""
        return enforce_secure_cookie(
            cookie_str,
            http_only=self.http_only,
            secure=self.secure,
            same_site=self.same_site,
            path=self.path,
        )

    def flask_after_request(self, response):
        """
        Flask after_request handler.

        Example:
            cookies = SecureCookieDefaults()

            @app.after_request
            def secure_cookies(response):
                return cookies.flask_after_request(response)
        """
        headers = response.headers.getlist("Set-Cookie")
        if headers:
            # Remove existing Set-Cookie headers
            del response.headers["Set-Cookie"]
            for cookie in headers:
                response.headers.add("Set-Cookie", self.enforce(cookie))
        return response


def create_secure_cookies(
    http_only: bool = True,
    secure: Optional[bool] = None,
    same_site: Optional[str] = "Lax",
    path: Optional[str] = None,
) -> SecureCookieDefaults:
    """
    Create a secure cookie enforcer.

    Example:
        cookies = create_secure_cookies(same_site="Strict")
    """
    return SecureCookieDefaults(
        http_only=http_only,
        secure=secure,
        same_site=same_site,
        path=path,
    )
