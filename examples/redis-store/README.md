# Redis Store Examples for Distributed Rate Limiting

Shield supports pluggable stores for rate limiting. This enables distributed rate limiting across multiple server instances using Redis (or any other shared storage).

## Why Redis?

The default in-memory store works great for single-instance deployments. However, in production with multiple server instances (load-balanced), each instance maintains its own counter - meaning a user could make 100 requests to server A AND 100 requests to server B.

Redis provides a shared counter that all instances can read/write, ensuring consistent rate limiting across your entire infrastructure.

## Examples

- **Node.js**: `node-redis-store.ts` - TypeScript implementation using `ioredis`
- **Go**: `go-redis-store.go` - Go implementation using `go-redis/redis`
- **Python**: `python-redis-store.py` - Python implementation using `redis-py`

## Prerequisites

1. Install Redis locally or use a managed Redis service
2. Install the Redis client library for your language

```bash
# Node.js
npm install ioredis

# Go
go get github.com/redis/go-redis/v9

# Python
pip install redis
```

## Usage

### Node.js

```typescript
import shield from '@aspect.dev/shield-node';
import { RedisRateLimitStore } from './node-redis-store';

const redisStore = new RedisRateLimitStore({
  host: 'localhost',
  port: 6379,
  keyPrefix: 'shield:ratelimit:',
});

app.use(shield({
  rateLimit: {
    max: 100,
    windowMs: 60000,
    store: redisStore,
  },
}));

// Cleanup on shutdown
process.on('SIGTERM', () => redisStore.close());
```

### Go

```go
import (
    "github.com/aspect.dev/shield-go"
    "github.com/redis/go-redis/v9"
)

rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
store := NewRedisStore(rdb, "shield:ratelimit:", time.Minute)

s := shield.NewWithConfig(shield.Config{
    RateLimit:    true,
    RateLimitMax: 100,
})
s.SetRateLimitStore(store)

// Cleanup on shutdown
defer store.Close()
```

### Python

```python
from shield import Shield, RateLimiter
from redis_store import RedisRateLimitStore
import redis

redis_client = redis.Redis(host='localhost', port=6379)
store = RedisRateLimitStore(redis_client, key_prefix='shield:ratelimit:')

limiter = RateLimiter(
    max_requests=100,
    window_ms=60000,
    store=store,
)

# Or with Flask
from shield import Shield
shield = Shield(app, rate_limiter_store=store)
```

## Best Practices

1. **Key Prefix**: Always use a unique prefix (e.g., `shield:ratelimit:`) to avoid collisions with other Redis keys
2. **TTL**: Set TTL on Redis keys to auto-cleanup expired entries
3. **Connection Pooling**: Use connection pooling in production
4. **Graceful Shutdown**: Always close the store/connection on shutdown
5. **Fallback**: Consider implementing a fallback to in-memory store if Redis is unavailable

## High Availability

For production, consider:
- Redis Sentinel for automatic failover
- Redis Cluster for horizontal scaling
- Connection retry logic with exponential backoff
