"""
Arcis Middleware - Error Handler

Production-safe error handler that hides sensitive details.
Prevents stack traces, DB errors, and internal info from leaking to clients.
"""

import re
import traceback
import logging
from typing import Any, Callable, Dict, Optional

_logger = logging.getLogger(__name__)

# Patterns that indicate database or infrastructure internals in error messages.
_SENSITIVE_ERROR_PATTERNS = [
    # SQL database errors
    re.compile(r"\b(SQLITE_ERROR|SQLSTATE|ORA-\d|PG::|mysql_|pg_query|ECONNREFUSED)", re.IGNORECASE),
    re.compile(r"\b(syntax error at or near|relation \".*\" does not exist)", re.IGNORECASE),
    re.compile(r"\b(column \".*\" (does not exist|of relation))", re.IGNORECASE),
    re.compile(r"\b(duplicate key value violates unique constraint)", re.IGNORECASE),
    re.compile(r"\b(table .* doesn't exist|unknown column)", re.IGNORECASE),
    # MongoDB errors
    re.compile(r"\b(MongoError|MongoServerError|MongoNetworkError|E11000 duplicate key)", re.IGNORECASE),
    # Redis errors
    re.compile(r"\b(WRONGTYPE|CROSSSLOT|CLUSTERDOWN|READONLY|ReplyError)", re.IGNORECASE),
    # Connection strings and DSNs
    re.compile(r"\b(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://)", re.IGNORECASE),
    # Stack traces with file paths
    re.compile(r"\bat\s+.*\.(js|ts|py|go|java):\d+", re.IGNORECASE),
    # Python tracebacks
    re.compile(r'File ".*\.py", line \d+', re.IGNORECASE),
    # Internal IP addresses
    re.compile(r"\b(127\.0\.0\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
]

GENERIC_ERROR = "Internal Server Error"


def contains_sensitive_info(message: str) -> bool:
    """Check if an error message contains sensitive infrastructure details."""
    return any(pattern.search(message) for pattern in _SENSITIVE_ERROR_PATTERNS)


class ErrorHandler:
    """
    Production-safe error handler that hides sensitive details.

    Prevents information leakage by:
    - Hiding stack traces in production
    - Hiding error messages unless explicitly exposed
    - Scrubbing database errors, connection strings, and internal IPs

    Example:
        handler = ErrorHandler(is_dev=False)
        response = handler.handle(exception, status_code=500)
    """

    def __init__(
        self,
        is_dev: bool = False,
        logger: Optional[Any] = None,
        log_errors: bool = True,
        custom_handler: Optional[Callable] = None,
    ):
        self.is_dev = is_dev
        self.logger = logger
        self.log_errors = log_errors
        self.custom_handler = custom_handler

    def _log_error(self, error: Exception, status_code: int, **extra: Any) -> None:
        """Log full error details server-side."""
        if not self.log_errors:
            return

        log_data = {
            "error": str(error),
            "status_code": status_code,
            "traceback": traceback.format_exc(),
            **extra,
        }

        if self.logger:
            self.logger.error("Request error", log_data)
        else:
            _logger.error("[arcis] Request error: %s", log_data)

    def _safe_message(self, error: Exception, status_code: int, expose: bool = False) -> str:
        """
        Get a client-safe error message.

        Args:
            error: The exception
            status_code: HTTP status code
            expose: Whether the caller explicitly marked this error as safe to expose
        """
        message = str(error)
        should_expose = self.is_dev or expose

        if not should_expose:
            return GENERIC_ERROR

        # Even when exposed, scrub DB/infra details in production
        if contains_sensitive_info(message) and not self.is_dev:
            return GENERIC_ERROR

        return message

    def handle(
        self,
        error: Exception,
        status_code: int = 500,
        expose: bool = False,
        **extra: Any,
    ) -> Dict[str, Any]:
        """
        Handle an error and return a safe response dict.

        Args:
            error: The exception to handle
            status_code: HTTP status code (default 500)
            expose: Whether the error message is safe to show to clients
            **extra: Additional context for logging

        Returns:
            Dict with safe error response
        """
        self._log_error(error, status_code, **extra)

        response: Dict[str, Any] = {
            "error": self._safe_message(error, status_code, expose),
        }

        # Only show details in development
        if self.is_dev:
            response["details"] = str(error)
            response["stack"] = traceback.format_exc()

        return response

    def flask_handler(self, error: Exception):
        """
        Flask error handler.

        Example:
            handler = ErrorHandler()
            app.register_error_handler(500, handler.flask_handler)
        """
        from flask import jsonify

        status_code = getattr(error, "code", 500) or 500
        expose = getattr(error, "expose", False)
        response = jsonify(self.handle(error, status_code, expose=expose))
        response.status_code = status_code
        return response

    def fastapi_handler(self, request: Any, error: Exception):
        """
        FastAPI/Starlette exception handler.

        Example:
            handler = ErrorHandler()
            app.add_exception_handler(Exception, handler.fastapi_handler)
        """
        from starlette.responses import JSONResponse

        status_code = getattr(error, "status_code", 500) or 500
        expose = getattr(error, "expose", False)
        body = self.handle(
            error,
            status_code,
            expose=expose,
            path=str(request.url),
            method=request.method,
        )
        return JSONResponse(content=body, status_code=status_code)

    def django_handler(self, request: Any, error: Exception, status_code: int = 500):
        """
        Django error handler.

        Example:
            handler = ErrorHandler()
            # in views.py
            def handler500(request):
                return handler.django_handler(request, Exception("server error"))
        """
        from django.http import JsonResponse

        expose = getattr(error, "expose", False)
        body = self.handle(
            error,
            status_code,
            expose=expose,
            path=request.path,
            method=request.method,
        )
        return JsonResponse(body, status=status_code)


def create_error_handler(
    is_dev: bool = False,
    logger: Optional[Any] = None,
    log_errors: bool = True,
    custom_handler: Optional[Callable] = None,
) -> ErrorHandler:
    """
    Create an error handler.

    Example:
        handler = create_error_handler(is_dev=os.environ.get('FLASK_ENV') == 'development')
    """
    return ErrorHandler(
        is_dev=is_dev,
        logger=logger,
        log_errors=log_errors,
        custom_handler=custom_handler,
    )
