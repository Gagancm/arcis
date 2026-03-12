"""
HTTP Header Injection Sanitizer Tests
Tests for arcis/sanitizers/headers.py
"""

import pytest
from arcis.sanitizers.headers import (
    sanitize_header_value,
    sanitize_headers,
    detect_header_injection,
)


class TestSanitizeHeaderValueCRLF:
    """Test CRLF injection prevention."""

    def test_strips_crlf_sequence(self):
        result = sanitize_header_value("value\r\nX-Injected: evil")
        assert "\r" not in result
        assert "\n" not in result
        assert result == "valueX-Injected: evil"

    def test_strips_bare_carriage_return(self):
        result = sanitize_header_value("value\rinjected")
        assert "\r" not in result
        assert result == "valueinjected"

    def test_strips_bare_newline(self):
        result = sanitize_header_value("value\ninjected")
        assert "\n" not in result
        assert result == "valueinjected"

    def test_strips_multiple_crlf_sequences(self):
        result = sanitize_header_value("a\r\nb\r\nc")
        assert result == "abc"

    def test_strips_mixed_cr_lf_crlf(self):
        result = sanitize_header_value("a\rb\nc\r\nd")
        assert result == "abcd"


class TestSanitizeHeaderValueNullByte:
    """Test null byte injection prevention."""

    def test_strips_null_bytes(self):
        result = sanitize_header_value("value\0truncated")
        assert "\0" not in result
        assert result == "valuetruncated"

    def test_strips_null_bytes_combined_with_crlf(self):
        result = sanitize_header_value("value\0\r\nevil")
        assert result == "valueevil"


class TestSanitizeHeaderValueResponseSplitting:
    """Test prevention of HTTP response splitting attacks."""

    def test_prevents_response_splitting(self):
        result = sanitize_header_value(
            "valid\r\n\r\n<html><script>alert(1)</script></html>"
        )
        assert "\r" not in result
        assert "\n" not in result
        assert "<html>" in result

    def test_prevents_set_cookie_injection(self):
        result = sanitize_header_value(
            "en\r\nSet-Cookie: session=hijacked"
        )
        assert "\r\n" not in result
        assert result == "enSet-Cookie: session=hijacked"

    def test_prevents_location_header_injection(self):
        result = sanitize_header_value(
            "ok\r\nLocation: http://evil.com"
        )
        assert result == "okLocation: http://evil.com"


class TestSanitizeHeaderValueSafeInput:
    """Test that safe inputs pass through unchanged."""

    def test_preserves_normal_content_type(self):
        assert sanitize_header_value("text/html; charset=utf-8") == \
            "text/html; charset=utf-8"

    def test_preserves_urls(self):
        assert sanitize_header_value("https://example.com/path?q=1") == \
            "https://example.com/path?q=1"

    def test_preserves_bearer_tokens(self):
        assert sanitize_header_value("Bearer eyJhbGciOiJIUzI1NiJ9.test") == \
            "Bearer eyJhbGciOiJIUzI1NiJ9.test"

    def test_preserves_cache_control(self):
        assert sanitize_header_value("no-cache, no-store, must-revalidate") == \
            "no-cache, no-store, must-revalidate"

    def test_preserves_empty_string(self):
        assert sanitize_header_value("") == ""


class TestSanitizeHeaderValueEdgeCases:
    """Test edge cases."""

    def test_rejects_non_string_input(self):
        with pytest.raises(TypeError):
            sanitize_header_value(123)

    def test_rejects_none_input(self):
        with pytest.raises(TypeError):
            sanitize_header_value(None)

    def test_string_with_only_crlf(self):
        assert sanitize_header_value("\r\n") == ""

    def test_consecutive_null_bytes(self):
        assert sanitize_header_value("\0\0\0") == ""

    def test_unicode_content(self):
        assert sanitize_header_value("value-with-émojis-and-ñ") == \
            "value-with-émojis-and-ñ"


class TestSanitizeHeaders:
    """Test sanitize_headers (dict of header key-value pairs)."""

    def test_sanitizes_both_keys_and_values(self):
        result = sanitize_headers({
            "X-Custom\r\n": "value\r\ninjected",
            "Content-Type": "text/html",
        })
        assert "X-Custom\r\n" not in result
        assert result["X-Custom"] == "valueinjected"
        assert result["Content-Type"] == "text/html"

    def test_rejects_non_dict_input(self):
        with pytest.raises(TypeError):
            sanitize_headers(None)

    def test_rejects_string_input(self):
        with pytest.raises(TypeError):
            sanitize_headers("string")

    def test_handles_empty_dict(self):
        assert sanitize_headers({}) == {}

    def test_coerces_non_string_values(self):
        result = sanitize_headers({"X-Number": 42})
        assert result["X-Number"] == "42"

    def test_sanitizes_multiple_headers(self):
        result = sanitize_headers({
            "X-A": "a\r\nb",
            "X-B": "c\nd",
            "X-C": "safe",
        })
        assert result["X-A"] == "ab"
        assert result["X-B"] == "cd"
        assert result["X-C"] == "safe"


class TestDetectHeaderInjection:
    """Test detect_header_injection."""

    def test_detects_crlf(self):
        assert detect_header_injection("value\r\nevil") is True

    def test_detects_bare_cr(self):
        assert detect_header_injection("value\revil") is True

    def test_detects_bare_lf(self):
        assert detect_header_injection("value\nevil") is True

    def test_detects_null_byte(self):
        assert detect_header_injection("value\0evil") is True

    def test_returns_false_for_safe_input(self):
        assert detect_header_injection("application/json") is False

    def test_returns_false_for_empty_string(self):
        assert detect_header_injection("") is False

    def test_returns_false_for_non_string(self):
        assert detect_header_injection(123) is False

    def test_returns_false_for_none(self):
        assert detect_header_injection(None) is False
