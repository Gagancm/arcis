"""
Redis Rate Limit Store for Arcis (Python)

Provides distributed rate limiting using Redis as the backing store.
This enables consistent rate limiting across multiple server instances.

Usage:
    from redis import Redis
    from arcis.stores.redis import RedisRateLimitStore
    from arcis import RateLimiter

    redis_client = Redis(host='localhost', port=6379)
    store = RedisRateLimitStore(redis_client)

    limiter = RateLimiter(max_requests=100, window_ms=60000, store=store)

    # Or with Flask
    from arcis import Arcis
    arcis = Arcis(app, rate_limiter_store=store)
"""

import time
from typing import Optional, Dict, Any, Protocol
from dataclasses import dataclass


class RateLimitStoreProtocol(Protocol):
    """Protocol defining the interface for rate limit stores."""
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get rate limit entry for a key."""
        ...
    
    def set(self, key: str, count: int, reset_time: float) -> None:
        """Set rate limit entry for a key."""
        ...
    
    def increment(self, key: str) -> int:
        """Increment count for a key and return new count."""
        ...
    
    def cleanup(self) -> None:
        """Remove expired entries (optional for Redis as TTL handles this)."""
        ...
    
    def close(self) -> None:
        """Close the store and release resources."""
        ...


@dataclass
class RedisStoreOptions:
    """Configuration options for Redis rate limit store."""
    
    key_prefix: str = "arcis:ratelimit:"
    """Prefix for all rate limit keys."""
    
    window_ms: int = 60000
    """Rate limit window in milliseconds (for TTL calculation)."""
    
    ttl_buffer_seconds: int = 1
    """Extra seconds to add to TTL to prevent edge cases."""
    
    use_lua_script: bool = True
    """Use Lua script for atomic increment-or-create operations."""


# Lua script for atomic increment-or-create
INCR_SCRIPT = """
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
    Redis-backed rate limit store for distributed rate limiting.
    
    Features:
    - Atomic increment operations using Redis INCR or Lua scripts
    - Automatic key expiration using TTL
    - Thread-safe for multi-threaded applications
    - Graceful degradation on Redis errors (fails open)
    
    Example:
        >>> from redis import Redis
        >>> redis_client = Redis(host='localhost', port=6379)
        >>> store = RedisRateLimitStore(redis_client)
        >>> 
        >>> # Check rate limit
        >>> entry = store.get('user:123')
        >>> if entry is None:
        ...     store.set('user:123', 1, time.time() * 1000 + 60000)
        ... else:
        ...     new_count = store.increment('user:123')
    """
    
    def __init__(
        self,
        redis_client,
        options: Optional[RedisStoreOptions] = None,
        key_prefix: Optional[str] = None,
        window_ms: Optional[int] = None,
    ):
        """
        Initialize the Redis rate limit store.
        
        Args:
            redis_client: A redis.Redis client instance
            options: RedisStoreOptions for configuration
            key_prefix: Override for key prefix (shorthand)
            window_ms: Override for window in ms (shorthand)
        """
        self._redis = redis_client
        self._closed = False
        
        # Handle options
        if options is None:
            options = RedisStoreOptions()
        
        self._key_prefix = key_prefix or options.key_prefix
        self._window_ms = window_ms or options.window_ms
        self._ttl_buffer = options.ttl_buffer_seconds
        self._use_lua = options.use_lua_script
        
        # Register Lua script if using atomic operations
        self._incr_script = None
        if self._use_lua:
            self._incr_script = self._redis.register_script(INCR_SCRIPT)
    
    def _build_key(self, key: str) -> str:
        """Build the full Redis key with prefix."""
        return f"{self._key_prefix}{key}"
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get rate limit entry for a key.
        
        Args:
            key: The rate limit key (e.g., IP address)
            
        Returns:
            Dict with 'count' and 'reset_time' keys, or None if not found/expired
        """
        if self._closed:
            return None
        
        try:
            full_key = self._build_key(key)
            data = self._redis.hgetall(full_key)
            
            if not data:
                return None
            
            # Redis returns bytes, decode them
            count_bytes = data.get(b'count') or data.get('count')
            reset_time_bytes = data.get(b'reset_time') or data.get('reset_time')
            
            if not count_bytes or not reset_time_bytes:
                return None
            
            count = int(count_bytes)
            reset_time = float(reset_time_bytes)
            
            # Check if expired
            now = time.time() * 1000
            if reset_time < now:
                return None
            
            return {
                'count': count,
                'reset_time': reset_time,
            }
            
        except Exception as e:
            print(f"[Arcis Redis Store] Get error: {e}")
            return None
    
    def set(self, key: str, count: int, reset_time: float) -> None:
        """
        Set rate limit entry for a key.
        
        Args:
            key: The rate limit key
            count: Current request count
            reset_time: Reset time in milliseconds since epoch
        """
        if self._closed:
            return
        
        try:
            full_key = self._build_key(key)
            
            # Use pipeline for atomic set + expire
            pipe = self._redis.pipeline()
            pipe.hset(full_key, mapping={
                'count': count,
                'reset_time': int(reset_time),
            })
            
            # Calculate TTL in milliseconds
            now = time.time() * 1000
            ttl_ms = max(int(reset_time - now), self._window_ms) + (self._ttl_buffer * 1000)
            pipe.pexpire(full_key, ttl_ms)
            
            pipe.execute()
            
        except Exception as e:
            print(f"[Arcis Redis Store] Set error: {e}")
    
    def increment(self, key: str) -> int:
        """
        Atomically increment the count for a key.
        
        If using Lua scripts (default), this is a single atomic operation.
        Otherwise, uses HINCRBY which may have race conditions for new keys.
        
        Args:
            key: The rate limit key
            
        Returns:
            The new count after incrementing (1 on error - fails open)
        """
        if self._closed:
            return 1
        
        try:
            full_key = self._build_key(key)
            now = int(time.time() * 1000)
            
            if self._use_lua and self._incr_script:
                # Atomic increment-or-create using Lua script
                result = self._incr_script(
                    keys=[full_key],
                    args=[self._window_ms, now]
                )
                return int(result[0])
            else:
                # Fallback to HINCRBY (may have race conditions for new keys)
                new_count = self._redis.hincrby(full_key, 'count', 1)
                return new_count
                
        except Exception as e:
            print(f"[Arcis Redis Store] Increment error: {e}")
            return 1  # Fail open
    
    def cleanup(self) -> None:
        """
        Cleanup expired entries.
        
        Note: With Redis, this is handled automatically by TTL.
        This method exists for interface compatibility.
        """
        pass  # Redis TTL handles cleanup automatically
    
    def close(self) -> None:
        """
        Close the store.
        
        Note: This does NOT close the underlying Redis client,
        as it may be shared with other parts of the application.
        """
        self._closed = True
    
    def close_with_client(self) -> None:
        """Close the store AND the underlying Redis client."""
        self._closed = True
        self._redis.close()
    
    def ping(self) -> bool:
        """Check if Redis is reachable."""
        try:
            return self._redis.ping()
        except Exception:
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about rate limit keys.
        
        Returns:
            Dict with 'key_count' and other stats
        """
        if self._closed:
            return {'key_count': 0, 'error': 'Store is closed'}
        
        try:
            pattern = f"{self._key_prefix}*"
            key_count = 0
            
            # Use SCAN to count keys (memory efficient)
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=pattern, count=100)
                key_count += len(keys)
                if cursor == 0:
                    break
            
            return {
                'key_count': key_count,
                'key_prefix': self._key_prefix,
                'window_ms': self._window_ms,
            }
            
        except Exception as e:
            return {'key_count': 0, 'error': str(e)}


class AsyncRedisRateLimitStore:
    """
    Async Redis-backed rate limit store for async frameworks (FastAPI, aiohttp).
    
    Uses aioredis or redis.asyncio for non-blocking operations.
    
    Example:
        >>> import redis.asyncio as redis
        >>> from redis_store import AsyncRedisRateLimitStore
        >>> 
        >>> redis_client = redis.Redis(host='localhost', port=6379)
        >>> store = AsyncRedisRateLimitStore(redis_client)
        >>> 
        >>> # In async context
        >>> entry = await store.get('user:123')
    """
    
    def __init__(
        self,
        redis_client,
        options: Optional[RedisStoreOptions] = None,
        key_prefix: Optional[str] = None,
        window_ms: Optional[int] = None,
    ):
        """
        Initialize the async Redis rate limit store.
        
        Args:
            redis_client: An async redis client (redis.asyncio.Redis)
            options: RedisStoreOptions for configuration
            key_prefix: Override for key prefix (shorthand)
            window_ms: Override for window in ms (shorthand)
        """
        self._redis = redis_client
        self._closed = False
        
        if options is None:
            options = RedisStoreOptions()
        
        self._key_prefix = key_prefix or options.key_prefix
        self._window_ms = window_ms or options.window_ms
        self._ttl_buffer = options.ttl_buffer_seconds
        self._use_lua = options.use_lua_script
        
        self._incr_script = None
        if self._use_lua:
            self._incr_script = self._redis.register_script(INCR_SCRIPT)
    
    def _build_key(self, key: str) -> str:
        return f"{self._key_prefix}{key}"
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get rate limit entry for a key (async)."""
        if self._closed:
            return None
        
        try:
            full_key = self._build_key(key)
            data = await self._redis.hgetall(full_key)
            
            if not data:
                return None
            
            count_bytes = data.get(b'count') or data.get('count')
            reset_time_bytes = data.get(b'reset_time') or data.get('reset_time')
            
            if not count_bytes or not reset_time_bytes:
                return None
            
            count = int(count_bytes)
            reset_time = float(reset_time_bytes)
            
            now = time.time() * 1000
            if reset_time < now:
                return None
            
            return {'count': count, 'reset_time': reset_time}
            
        except Exception as e:
            print(f"[Arcis Redis Store] Async get error: {e}")
            return None
    
    async def set(self, key: str, count: int, reset_time: float) -> None:
        """Set rate limit entry for a key (async)."""
        if self._closed:
            return
        
        try:
            full_key = self._build_key(key)
            
            pipe = self._redis.pipeline()
            pipe.hset(full_key, mapping={
                'count': count,
                'reset_time': int(reset_time),
            })
            
            now = time.time() * 1000
            ttl_ms = max(int(reset_time - now), self._window_ms) + (self._ttl_buffer * 1000)
            pipe.pexpire(full_key, ttl_ms)
            
            await pipe.execute()
            
        except Exception as e:
            print(f"[Arcis Redis Store] Async set error: {e}")
    
    async def increment(self, key: str) -> int:
        """Atomically increment the count for a key (async)."""
        if self._closed:
            return 1
        
        try:
            full_key = self._build_key(key)
            now = int(time.time() * 1000)
            
            if self._use_lua and self._incr_script:
                result = await self._incr_script(
                    keys=[full_key],
                    args=[self._window_ms, now]
                )
                return int(result[0])
            else:
                new_count = await self._redis.hincrby(full_key, 'count', 1)
                return new_count
                
        except Exception as e:
            print(f"[Arcis Redis Store] Async increment error: {e}")
            return 1
    
    async def cleanup(self) -> None:
        """Cleanup (no-op for Redis - TTL handles it)."""
        pass
    
    async def close(self) -> None:
        """Close the store."""
        self._closed = True
    
    async def close_with_client(self) -> None:
        """Close the store AND the underlying Redis client."""
        self._closed = True
        await self._redis.close()
    
    async def ping(self) -> bool:
        """Check if Redis is reachable."""
        try:
            return await self._redis.ping()
        except Exception:
            return False


# Convenience factory functions
def create_redis_store(
    host: str = 'localhost',
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None,
    **options
) -> RedisRateLimitStore:
    """
    Create a Redis rate limit store with a new Redis client.
    
    Example:
        >>> store = create_redis_store(host='localhost', port=6379)
    """
    import redis
    
    client = redis.Redis(
        host=host,
        port=port,
        db=db,
        password=password,
        decode_responses=False,  # We handle decoding ourselves
    )
    
    return RedisRateLimitStore(client, **options)


async def create_async_redis_store(
    host: str = 'localhost',
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None,
    **options
) -> AsyncRedisRateLimitStore:
    """
    Create an async Redis rate limit store with a new Redis client.
    
    Example:
        >>> store = await create_async_redis_store(host='localhost', port=6379)
    """
    import redis.asyncio as redis
    
    client = redis.Redis(
        host=host,
        port=port,
        db=db,
        password=password,
        decode_responses=False,
    )
    
    return AsyncRedisRateLimitStore(client, **options)
