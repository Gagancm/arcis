"""
Shield Redis Rate Limit Store
==============================

Distributed rate limiting using Redis as the backing store.
Enables consistent rate limiting across multiple server instances.

Usage (sync — Flask, Django):
    from redis import Redis
    from shield.stores.redis import RedisRateLimitStore
    from shield import RateLimiter

    redis_client = Redis(host='localhost', port=6379)
    store = RedisRateLimitStore(redis_client)
    limiter = RateLimiter(max_requests=100, window_ms=60000, store=store)

Usage (async — FastAPI):
    import redis.asyncio as redis
    from shield.stores.redis import AsyncRedisRateLimitStore
    from shield.fastapi import ShieldMiddleware

    redis_client = redis.Redis(host='localhost', port=6379)
    store = AsyncRedisRateLimitStore(redis_client)
    app.add_middleware(ShieldMiddleware, store=store)

Requires:
    pip install shield-security[redis]
    # or: pip install redis
"""

import time
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class RedisStoreOptions:
    """Configuration options for the Redis rate limit store."""

    key_prefix: str = "shield:ratelimit:"
    """Prefix applied to all Redis keys."""

    window_ms: int = 60000
    """Rate limit window in milliseconds (used for TTL calculation)."""

    ttl_buffer_seconds: int = 1
    """Extra seconds added to TTL to avoid edge-case expiry races."""

    use_lua_script: bool = True
    """Use a Lua script for atomic increment-or-create. Recommended."""


# Lua script: atomic increment-or-create in a single round-trip.
_INCR_SCRIPT = """
local key = KEYS[1]
local window_ms = tonumber(ARGV[1])
local now = tonumber(ARGV[2])

local count = redis.call('HGET', key, 'count')
local reset_time = redis.call('HGET', key, 'reset_time')

count = tonumber(count) or 0
reset_time = tonumber(reset_time) or 0

if reset_time == 0 or reset_time < now then
    count = 1
    reset_time = now + window_ms
    redis.call('HSET', key, 'count', count, 'reset_time', reset_time)
    redis.call('PEXPIRE', key, window_ms + 1000)
else
    count = redis.call('HINCRBY', key, 'count', 1)
end

return {count, reset_time}
"""


class RedisRateLimitStore:
    """
    Redis-backed rate limit store for sync frameworks (Flask, Django).

    Features:
    - Atomic increment via Lua script (single round-trip, no race conditions)
    - Automatic key expiration via Redis TTL (no cleanup thread needed)
    - Graceful degradation on Redis errors (fails open)
    - Thread-safe for multi-threaded WSGI servers

    Example:
        from redis import Redis
        from shield.stores.redis import RedisRateLimitStore
        from shield import RateLimiter

        store = RedisRateLimitStore(Redis(host='localhost', port=6379))
        limiter = RateLimiter(max_requests=100, window_ms=60000, store=store)
    """

    def __init__(
        self,
        redis_client,
        options: Optional[RedisStoreOptions] = None,
        key_prefix: Optional[str] = None,
        window_ms: Optional[int] = None,
    ):
        self._redis = redis_client
        self._closed = False

        opts = options or RedisStoreOptions()
        self._key_prefix = key_prefix or opts.key_prefix
        self._window_ms = window_ms or opts.window_ms
        self._ttl_buffer = opts.ttl_buffer_seconds
        self._use_lua = opts.use_lua_script

        self._incr_script = None
        if self._use_lua:
            self._incr_script = self._redis.register_script(_INCR_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._key_prefix}{key}"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if self._closed:
            return None
        try:
            data = self._redis.hgetall(self._key(key))
            if not data:
                return None

            count = data.get(b"count") or data.get("count")
            reset_time = data.get(b"reset_time") or data.get("reset_time")
            if not count or not reset_time:
                return None

            reset_time = float(reset_time)
            if reset_time < time.time() * 1000:
                return None

            return {"count": int(count), "reset_time": reset_time}
        except Exception as e:
            print(f"[Shield RedisStore] get error: {e}")
            return None

    def set(self, key: str, count: int, reset_time: float) -> None:
        if self._closed:
            return
        try:
            full_key = self._key(key)
            now_ms = time.time() * 1000
            ttl_ms = max(int(reset_time - now_ms), self._window_ms) + (self._ttl_buffer * 1000)

            pipe = self._redis.pipeline()
            pipe.hset(full_key, mapping={"count": count, "reset_time": int(reset_time)})
            pipe.pexpire(full_key, ttl_ms)
            pipe.execute()
        except Exception as e:
            print(f"[Shield RedisStore] set error: {e}")

    def increment(self, key: str) -> int:
        if self._closed:
            return 1
        try:
            now_ms = int(time.time() * 1000)
            if self._use_lua and self._incr_script:
                result = self._incr_script(
                    keys=[self._key(key)],
                    args=[self._window_ms, now_ms],
                )
                return int(result[0])
            return self._redis.hincrby(self._key(key), "count", 1)
        except Exception as e:
            print(f"[Shield RedisStore] increment error: {e}")
            return 1  # fail open

    def cleanup(self) -> None:
        """No-op — Redis TTL handles expiry automatically."""
        pass

    def close(self) -> None:
        """Mark store as closed. Does not close the Redis client."""
        self._closed = True

    def ping(self) -> bool:
        try:
            return bool(self._redis.ping())
        except Exception:
            return False


class AsyncRedisRateLimitStore:
    """
    Async Redis-backed rate limit store for async frameworks (FastAPI, aiohttp).

    Uses redis.asyncio for non-blocking operations.

    Example:
        import redis.asyncio as redis
        from shield.stores.redis import AsyncRedisRateLimitStore
        from shield.fastapi import ShieldMiddleware

        store = AsyncRedisRateLimitStore(redis.Redis(host='localhost', port=6379))
        app.add_middleware(ShieldMiddleware, store=store)
    """

    def __init__(
        self,
        redis_client,
        options: Optional[RedisStoreOptions] = None,
        key_prefix: Optional[str] = None,
        window_ms: Optional[int] = None,
    ):
        self._redis = redis_client
        self._closed = False

        opts = options or RedisStoreOptions()
        self._key_prefix = key_prefix or opts.key_prefix
        self._window_ms = window_ms or opts.window_ms
        self._ttl_buffer = opts.ttl_buffer_seconds
        self._use_lua = opts.use_lua_script

        self._incr_script = None
        if self._use_lua:
            self._incr_script = self._redis.register_script(_INCR_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._key_prefix}{key}"

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        if self._closed:
            return None
        try:
            data = await self._redis.hgetall(self._key(key))
            if not data:
                return None

            count = data.get(b"count") or data.get("count")
            reset_time = data.get(b"reset_time") or data.get("reset_time")
            if not count or not reset_time:
                return None

            reset_time = float(reset_time)
            if reset_time < time.time() * 1000:
                return None

            return {"count": int(count), "reset_time": reset_time}
        except Exception as e:
            print(f"[Shield AsyncRedisStore] get error: {e}")
            return None

    async def set(self, key: str, count: int, reset_time: float) -> None:
        if self._closed:
            return
        try:
            full_key = self._key(key)
            now_ms = time.time() * 1000
            ttl_ms = max(int(reset_time - now_ms), self._window_ms) + (self._ttl_buffer * 1000)

            pipe = self._redis.pipeline()
            pipe.hset(full_key, mapping={"count": count, "reset_time": int(reset_time)})
            pipe.pexpire(full_key, ttl_ms)
            await pipe.execute()
        except Exception as e:
            print(f"[Shield AsyncRedisStore] set error: {e}")

    async def increment(self, key: str) -> int:
        if self._closed:
            return 1
        try:
            now_ms = int(time.time() * 1000)
            if self._use_lua and self._incr_script:
                result = await self._incr_script(
                    keys=[self._key(key)],
                    args=[self._window_ms, now_ms],
                )
                return int(result[0])
            return await self._redis.hincrby(self._key(key), "count", 1)
        except Exception as e:
            print(f"[Shield AsyncRedisStore] increment error: {e}")
            return 1  # fail open

    async def cleanup(self) -> None:
        """No-op — Redis TTL handles expiry automatically."""
        pass

    async def close(self) -> None:
        """Mark store as closed. Does not close the Redis client."""
        self._closed = True

    async def ping(self) -> bool:
        try:
            return bool(await self._redis.ping())
        except Exception:
            return False
