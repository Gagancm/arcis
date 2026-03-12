"""
Arcis HTTP Header Injection & CRLF Injection prevention.

Prevents attackers from injecting newline characters (\\r\\n) into HTTP header
values, which can lead to response splitting, session fixation, XSS via
injected headers, and cache poisoning.
"""

import re
from typing import Dict

# Characters and sequences that enable header injection:
# - \r\n (CRLF) — HTTP header delimiter, enables response splitting
# - \r, \n alone — partial line breaks, some servers normalize to CRLF
# - \0 (null byte) — can truncate header values in some implementations
_HEADER_INJECTION_PATTERN = re.compile(r'\r\n|\r|\n|\0')


def sanitize_header_value(value: str) -> str:
    """
    Sanitize a header value by stripping CRLF sequences, bare CR/LF,
    and null bytes.

    Args:
        value: The header value to sanitize.

    Returns:
        Sanitized string with injection characters removed.

    Raises:
        TypeError: If value is not a string.

    Example:
        >>> sanitize_header_value("safe-value")
        'safe-value'
        >>> sanitize_header_value("value\\r\\nX-Injected: evil")
        'valueX-Injected: evil'
    """
    if not isinstance(value, str):
        raise TypeError(
            f"sanitize_header_value expects str, got {type(value).__name__}"
        )

    return _HEADER_INJECTION_PATTERN.sub('', value)


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Sanitize a dictionary of HTTP header key-value pairs.
    Strips CRLF/null bytes from both keys and values.

    Args:
        headers: Dictionary with header names as keys and values as values.

    Returns:
        New dictionary with sanitized header names and values.

    Raises:
        TypeError: If headers is not a dict.

    Example:
        >>> sanitize_headers({"X-Custom": "safe", "X-Bad\\r\\n": "value\\r\\ninjected"})
        {'X-Custom': 'safe', 'X-Bad': 'valueinjected'}
    """
    if not isinstance(headers, dict):
        raise TypeError(
            f"sanitize_headers expects dict, got {type(headers).__name__}"
        )

    result = {}
    for key, value in headers.items():
        sanitized_key = _HEADER_INJECTION_PATTERN.sub('', str(key))
        sanitized_value = _HEADER_INJECTION_PATTERN.sub('', str(value))
        result[sanitized_key] = sanitized_value
    return result


def detect_header_injection(value: str) -> bool:
    """
    Check if a string contains HTTP header injection patterns
    (CRLF, bare CR/LF, null bytes).

    Does not sanitize — use sanitize_header_value() for that.

    Args:
        value: The string to check.

    Returns:
        True if header injection patterns detected.
    """
    if not isinstance(value, str):
        return False

    return bool(_HEADER_INJECTION_PATTERN.search(value))
