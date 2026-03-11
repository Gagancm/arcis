"""
Arcis Middleware - Rate Limiter

RateLimitExceeded exception and RateLimiter class.
"""

import time
import threading
import atexit
from typing import Any, Callable, Dict, Optional

from ..stores.memory import InMemoryStore
from ..core.constants import DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_MS, DEFAULT_RATE_LIMIT_MESSAGE


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 0):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


class RateLimiter:
    """
    Rate limiter with configurable limits and window sizes.

    Example:
        limiter = RateLimiter(max_requests=100, window_ms=60000)
        try:
            result = limiter.check(request)
        except RateLimitExceeded as e:
            return error_response(e.message, e.retry_after)
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window_ms: int = DEFAULT_WINDOW_MS,
        message: str = DEFAULT_RATE_LIMIT_MESSAGE,
        key_func: Optional[Callable] = None,
        skip_func: Optional[Callable] = None,
        store: Optional[InMemoryStore] = None,
    ):
        if max_requests < 1:
            raise ValueError(f"max_requests must be >= 1, got {max_requests}")
        if window_ms < 1:
            raise ValueError(f"window_ms must be >= 1, got {window_ms}")

        self.max_requests = max_requests
        self.window_seconds = window_ms / 1000
        self.message = message
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self._store_provided = store is not None
        self.store = store or InMemoryStore()
        self._closed = False

        # Start cleanup thread only for in-memory store
        # External stores (e.g. Redis) handle their own expiry
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_event = threading.Event()
        if not self._store_provided:
            self._start_cleanup_thread()

        # Register cleanup on exit
        atexit.register(self.close)

    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        def cleanup_loop():
            while not self._cleanup_event.wait(timeout=self.window_seconds):
                if self._closed:
                    break
                self.store.cleanup()

        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def close(self):
        """Stop cleanup thread and release resources."""
        if self._closed:
            return
        self._closed = True
        self._cleanup_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1.0)
        self.store.close()

    def _default_key_func(self, request) -> str:
        """Default key function - uses client IP address.

        Checks X-Forwarded-For and X-Real-IP headers first so deployments
        behind reverse proxies (nginx, ALB, Cloudflare) get per-client buckets
        instead of sharing a single bucket for the proxy IP.
        """
        # Django — headers live in META with HTTP_ prefix
        if hasattr(request, 'META'):
            forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
            if forwarded:
                return forwarded.split(',')[0].strip()
            real_ip = request.META.get('HTTP_X_REAL_IP')
            if real_ip:
                return real_ip
            return request.META.get('REMOTE_ADDR', 'unknown')

        # Flask — headers via request.headers mapping
        if hasattr(request, 'remote_addr'):
            forwarded = request.headers.get('X-Forwarded-For') if hasattr(request, 'headers') else None
            if forwarded:
                return forwarded.split(',')[0].strip()
            real_ip = request.headers.get('X-Real-IP') if hasattr(request, 'headers') else None
            if real_ip:
                return real_ip
            return request.remote_addr or "unknown"

        # FastAPI/Starlette sync fallback
        if hasattr(request, 'client'):
            return request.client.host if request.client else "unknown"

        return "unknown"

    def check(self, request) -> Dict[str, Any]:
        """
        Check if request is within rate limit.
        Returns dict with limit info and raises RateLimitExceeded if exceeded.
        """
        if self._closed:
            # Fail open if closed
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

        if self.skip_func and self.skip_func(request):
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests, "reset": 0}

        key = self.key_func(request)
        now = time.time()

        entry = self.store.get(key)

        if not entry:
            self.store.set(key, 1, now + self.window_seconds)
            return {
                "allowed": True,
                "limit": self.max_requests,
                "remaining": self.max_requests - 1,
                "reset": int(self.window_seconds),
            }

        count = self.store.increment(key)
        remaining = max(0, self.max_requests - count)
        reset = int(entry.reset_time - now)

        if count > self.max_requests:
            raise RateLimitExceeded(self.message, reset)

        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": reset,
        }
