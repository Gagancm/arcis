"""
Arcis validation package.
"""

from .validators import Validator, ValidationError, validate_email, validate_url, validate_uuid
from .schema import SchemaValidator, create_validator
from .url import validate_url_ssrf, is_url_safe, ValidateUrlOptions, ValidateUrlResult
from .redirect import validate_redirect, is_redirect_safe, ValidateRedirectOptions, ValidateRedirectResult
from .file import validate_file, sanitize_filename, is_dangerous_extension, ValidateFileResult

__all__ = [
    "Validator",
    "ValidationError",
    "validate_email",
    "validate_url",
    "validate_uuid",
    "SchemaValidator",
    "create_validator",
    "validate_url_ssrf",
    "is_url_safe",
    "ValidateUrlOptions",
    "ValidateUrlResult",
    "validate_redirect",
    "is_redirect_safe",
    "ValidateRedirectOptions",
    "ValidateRedirectResult",
    "validate_file",
    "sanitize_filename",
    "is_dangerous_extension",
    "ValidateFileResult",
]
