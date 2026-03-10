"""
SecurityHeaders tests — extracted from tests/test_core.py.
"""

import pytest
from arcis.core import SecurityHeaders


class TestSecurityHeaders:
    """Test security headers functionality."""

    def test_default_headers_present(self):
        """Default security headers should be set."""
        headers = SecurityHeaders()
        h = headers.get_headers()

        assert "Content-Security-Policy" in h
        assert "X-Content-Type-Options" in h
        assert h["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in h
        assert h["X-Frame-Options"] == "DENY"
        assert "Strict-Transport-Security" in h
        assert "max-age=" in h["Strict-Transport-Security"]

    def test_custom_csp(self):
        """Should allow custom Content-Security-Policy."""
        custom_csp = "default-src 'none'"
        headers = SecurityHeaders(content_security_policy=custom_csp)
        h = headers.get_headers()

        assert h["Content-Security-Policy"] == custom_csp
