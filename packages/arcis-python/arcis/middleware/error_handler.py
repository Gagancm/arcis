"""
Arcis Middleware - Error Handler

ErrorHandler class and create_error_handler factory function.
"""

from typing import Any, Dict, Optional


class ErrorHandler:
    """
    Production-safe error handler that hides sensitive details.

    Example:
        handler = ErrorHandler(is_dev=False)
        response = handler.handle(exception, status_code=500)
    """

    def __init__(self, is_dev: bool = False, logger=None):
        self.is_dev = is_dev
        self.logger = logger

    def handle(self, error: Exception, status_code: int = 500) -> Dict[str, Any]:
        """
        Handle an error and return a safe response dict.
        In production, hides error details for 5xx errors.
        """
        # Log the error if logger provided
        if self.logger:
            self.logger.error("Request error", {
                "error": str(error),
                "status_code": status_code,
            })

        response: Dict[str, Any] = {}

        if status_code >= 500:
            response["error"] = "Internal Server Error"
        else:
            response["error"] = str(error)

        # Only show details in development
        if self.is_dev:
            response["details"] = str(error)
            import traceback
            response["stack"] = traceback.format_exc()

        return response

    def flask_handler(self, error: Exception):
        """Flask error handler."""
        from flask import jsonify
        status_code = getattr(error, 'code', 500) or 500
        response = jsonify(self.handle(error, status_code))
        response.status_code = status_code
        return response


def create_error_handler(is_dev: bool = False, logger=None) -> ErrorHandler:
    """
    Create an error handler.

    Example:
        handler = create_error_handler(is_dev=os.environ.get('FLASK_ENV') == 'development')
    """
    return ErrorHandler(is_dev=is_dev, logger=logger)
