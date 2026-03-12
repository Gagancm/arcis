"""
Arcis Middleware - Safe CORS

Secure CORS handler with safe defaults. Unlike permissive CORS libraries:
- No wildcard `*` when credentials are enabled
- `null` origin is always blocked
- `Vary: Origin` is always set for proper caching
- You must explicitly configure allowed origins
"""

import re
from typing import Callable, List, Optional, Pattern, Sequence, Union

DEFAULT_METHODS = ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"]
DEFAULT_HEADERS = ["Content-Type", "Authorization"]
DEFAULT_MAX_AGE = 600


def _is_origin_allowed(
    request_origin: str,
    allowed: Union[str, List[str], "Pattern[str]", Callable[[str], bool], bool],
) -> bool:
    """Check if an origin is allowed by the configured policy."""
    # 'null' origin is always blocked — sent by sandboxed iframes, data: URIs
    if request_origin == "null":
        return False

    if allowed is True:
        return True

    if isinstance(allowed, str):
        return request_origin == allowed

    if isinstance(allowed, list):
        return request_origin in allowed

    if isinstance(allowed, re.Pattern):
        return bool(allowed.match(request_origin))

    if callable(allowed):
        return allowed(request_origin)

    return False


class SafeCors:
    """
    Safe CORS handler.

    Args:
        origin: Allowed origins — string, list, regex, callable, or True (reflect, dev only)
        methods: Allowed HTTP methods
        allowed_headers: Allowed request headers
        exposed_headers: Headers exposed to the browser
        credentials: Allow credentials (cookies, auth headers)
        max_age: Preflight cache duration in seconds

    Example:
        cors = SafeCors(origin="https://myapp.com", credentials=True)
    """

    def __init__(
        self,
        origin: Union[str, List[str], "Pattern[str]", Callable[[str], bool], bool],
        methods: Optional[Sequence[str]] = None,
        allowed_headers: Optional[Sequence[str]] = None,
        exposed_headers: Optional[Sequence[str]] = None,
        credentials: bool = False,
        max_age: int = DEFAULT_MAX_AGE,
    ):
        self.origin = origin
        self.methods = list(methods) if methods else DEFAULT_METHODS
        self.allowed_headers = list(allowed_headers) if allowed_headers else DEFAULT_HEADERS
        self.exposed_headers = list(exposed_headers) if exposed_headers else []
        self.credentials = credentials
        self.max_age = max_age

    def get_headers(self, request_origin: Optional[str], method: str = "GET") -> dict:
        """
        Get CORS response headers for a request.

        Args:
            request_origin: The Origin header from the request (None if absent)
            method: The HTTP method of the request

        Returns:
            Dict of CORS headers to add to the response
        """
        headers: dict = {"Vary": "Origin"}

        # No origin = same-origin request, skip CORS headers
        if not request_origin:
            return headers

        if not _is_origin_allowed(request_origin, self.origin):
            return headers

        headers["Access-Control-Allow-Origin"] = request_origin

        if self.credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        if self.exposed_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(self.exposed_headers)

        # Preflight headers
        if method == "OPTIONS":
            headers["Access-Control-Allow-Methods"] = ", ".join(self.methods)
            headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
            headers["Access-Control-Max-Age"] = str(self.max_age)

        return headers

    def flask_handler(self, response):
        """
        Flask after_request handler.

        Example:
            cors = SafeCors(origin="https://myapp.com")

            @app.after_request
            def add_cors(response):
                return cors.flask_handler(response)
        """
        from flask import request

        origin = request.headers.get("Origin")
        headers = self.get_headers(origin, request.method)
        for key, value in headers.items():
            response.headers[key] = value

        if request.method == "OPTIONS" and "Access-Control-Allow-Origin" in headers:
            response.status_code = 204

        return response


def create_cors(
    origin: Union[str, List[str], "Pattern[str]", Callable[[str], bool], bool],
    methods: Optional[Sequence[str]] = None,
    allowed_headers: Optional[Sequence[str]] = None,
    exposed_headers: Optional[Sequence[str]] = None,
    credentials: bool = False,
    max_age: int = DEFAULT_MAX_AGE,
) -> SafeCors:
    """
    Create a safe CORS handler.

    Example:
        cors = create_cors(origin=["https://myapp.com", "https://admin.myapp.com"])
    """
    return SafeCors(
        origin=origin,
        methods=methods,
        allowed_headers=allowed_headers,
        exposed_headers=exposed_headers,
        credentials=credentials,
        max_age=max_age,
    )
