"""
ErrorHandler tests — extracted from tests/test_core.py.
"""

import pytest
from arcis.core import ErrorHandler


class TestErrorHandler:
    """Test ErrorHandler functionality aligned with TEST_VECTORS.json."""

    def test_production_mode_hides_details(self):
        """TEST_VECTORS: production mode should hide error details."""
        handler = ErrorHandler(is_dev=False)
        error = Exception("Database connection failed")
        response = handler.handle(error, status_code=500)

        assert "Internal Server Error" in response.get("error", "")
        assert "Database" not in response.get("error", "")
        assert "stack" not in response
        assert "details" not in response

    def test_production_mode_shows_client_errors(self):
        """Client errors (4xx) should show the error message even in production."""
        handler = ErrorHandler(is_dev=False)
        error = Exception("Invalid request data")
        response = handler.handle(error, status_code=400)

        assert "Invalid request data" in response.get("error", "")

    def test_development_mode_shows_details(self):
        """TEST_VECTORS: dev mode should show error details."""
        handler = ErrorHandler(is_dev=True)
        error = Exception("Something broke")
        response = handler.handle(error, status_code=500)

        assert "details" in response
        assert "Something broke" in response.get("details", "")

    def test_development_mode_shows_stack(self):
        """TEST_VECTORS: dev mode should include stack trace."""
        handler = ErrorHandler(is_dev=True)
        try:
            raise ValueError("Test error")
        except ValueError as e:
            response = handler.handle(e, status_code=500)

        assert "stack" in response
        assert len(response["stack"]) > 0
