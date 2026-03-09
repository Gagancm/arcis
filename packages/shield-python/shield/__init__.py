"""
Arcis Security Library for Python
===================================

One-line security for Flask, FastAPI, and Django applications.

Usage:
    # Flask
    from shield import Arcis
    app = Flask(__name__)
    arcis = Arcis(app)

    # Access sanitized JSON in routes
    from flask import g
    @app.route('/api', methods=['POST'])
    def api():
        data = g.json  # or g.sanitized_json

    # FastAPI
    from fastapi import FastAPI, Depends
    from shield.fastapi import ArcisMiddleware, get_json

    app = FastAPI()
    app.add_middleware(ArcisMiddleware)

    @app.post("/api")
    async def api(data: dict = Depends(get_json)):
        pass  # data is sanitized

    # FastAPI with async rate limiter (new!)
    from shield.fastapi import AsyncRateLimiter, create_rate_limit_dependency

    # Per-route rate limiting
    strict_limit = create_rate_limit_dependency(max_requests=10)

    @app.post("/login", dependencies=[Depends(strict_limit)])
    async def login():
        pass

    # Django (settings.py)
    MIDDLEWARE = ['shield.django.ArcisMiddleware', ...]

    # In views:
    from shield.django import get_json
    def my_view(request):
        data = get_json(request)

Cleanup:
    When your application shuts down, call arcis.close() to clean up
    background threads (rate limiter cleanup thread).

    # Flask example
    import atexit
    arcis = Arcis(app)
    atexit.register(arcis.close)
"""

from .core import (
    # Main class
    Arcis,
    # Core components
    Sanitizer,
    RateLimiter,
    RateLimitExceeded,
    RateLimitEntry,
    InMemoryStore,
    SecurityHeaders,
    Validator,
    ValidationError,
    SafeLogger,
    # Schema validation
    SchemaValidator,
    create_validator,
    # Error handling
    ErrorHandler,
    create_error_handler,
    # Exceptions
    InputTooLargeError,
    # Convenience functions
    sanitize_string,
    sanitize_dict,
    validate_email,
    validate_url,
    validate_uuid,
)

from .sanitizer import (
    sanitize_xss,
    sanitize_sql,
    sanitize_nosql,
    sanitize_path,
    sanitize_command,
)

# Async components (for FastAPI)
try:
    from .fastapi import (
        AsyncRateLimiter,
        AsyncRateLimitExceeded,
        AsyncInMemoryStore,
        AsyncRateLimitStore,
        create_rate_limit_dependency,
    )
    _HAS_ASYNC = True
except ImportError:
    _HAS_ASYNC = False

__version__ = "1.0.0"
__all__ = [
    # Main class
    "Arcis",
    # Core components
    "Sanitizer",
    "RateLimiter",
    "RateLimitExceeded",
    "RateLimitEntry",
    "InMemoryStore",
    "SecurityHeaders",
    "Validator",
    "ValidationError",
    "SafeLogger",
    # Schema validation
    "SchemaValidator",
    "create_validator",
    # Error handling
    "ErrorHandler",
    "create_error_handler",
    # Exceptions
    "InputTooLargeError",
    # Convenience functions
    "sanitize_string",
    "sanitize_dict",
    "sanitize_xss",
    "sanitize_sql",
    "sanitize_nosql",
    "sanitize_path",
    "sanitize_command",
    "validate_email",
    "validate_url",
    "validate_uuid",
]

# Add async exports if available
if _HAS_ASYNC:
    __all__.extend([
        "AsyncRateLimiter",
        "AsyncRateLimitExceeded",
        "AsyncInMemoryStore",
        "AsyncRateLimitStore",
        "create_rate_limit_dependency",
    ])

# Redis store is available as a separate submodule (requires redis extra):
#   from shield.stores.redis import RedisRateLimitStore       # sync (Flask/Django)
#   from shield.stores.redis import AsyncRedisRateLimitStore  # async (FastAPI)
#
# Install with: pip install arcis[redis]
