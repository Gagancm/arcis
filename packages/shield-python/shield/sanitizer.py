# Re-exports for convenience
from .core import (
    Sanitizer,
    sanitize_string,
    sanitize_dict,
)

# Specific sanitization functions
def sanitize_xss(value: str) -> str:
    """Sanitize string for XSS only."""
    return Sanitizer(xss=True, sql=False, nosql=False, path=False).sanitize_string(value)

def sanitize_sql(value: str) -> str:
    """Sanitize string for SQL injection only."""
    return Sanitizer(xss=False, sql=True, nosql=False, path=False).sanitize_string(value)

def sanitize_nosql(data: dict) -> dict:
    """Sanitize dict for NoSQL injection only."""
    return Sanitizer(xss=False, sql=False, nosql=True, path=False).sanitize_dict(data)

def sanitize_path(value: str) -> str:
    """Sanitize string for path traversal only."""
    return Sanitizer(xss=False, sql=False, nosql=False, path=True).sanitize_string(value)

def sanitize_command(value: str) -> str:
    """Sanitize string for command injection."""
    return Sanitizer(xss=False, sql=False, nosql=False, path=False, command=True).sanitize_string(value)
