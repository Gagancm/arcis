"""
Arcis In-Memory Rate Limit Store

Thread-safe in-memory store for rate limiting.
"""

import time
import threading
from typing import Dict, Optional

from ..core.types import RateLimitEntry


class InMemoryStore:
    """Thread-safe in-memory store for rate limiting."""
    def __init__(self):
        self._store: Dict[str, RateLimitEntry] = {}
        self._lock = threading.Lock()
        self._closed = False

    def get(self, key: str) -> Optional[RateLimitEntry]:
        """Return the rate limit entry for key, or None if missing/expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry and entry.reset_time < time.time():
                del self._store[key]
                return None
            return entry

    def set(self, key: str, count: int, reset_time: float):
        """Store a rate limit entry with the given count and reset timestamp."""
        with self._lock:
            self._store[key] = RateLimitEntry(count=count, reset_time=reset_time)

    def increment(self, key: str) -> int:
        """Increment the request count for a key. Creates entry if missing."""
        with self._lock:
            entry = self._store.get(key)
            if entry:
                entry.count += 1
                return entry.count
            # Entry doesn't exist - create it (defensive: should not happen in normal flow)
            # Use a default reset_time of 60s from now; caller should use set() for new entries
            self._store[key] = RateLimitEntry(count=1, reset_time=time.time() + 60)
            return 1

    def cleanup(self):
        """Remove expired entries."""
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._store.items() if v.reset_time < now]
            for k in expired:
                del self._store[k]

    def clear(self):
        """Clear all entries."""
        with self._lock:
            self._store.clear()

    def close(self):
        """Mark store as closed."""
        self._closed = True
        self.clear()
