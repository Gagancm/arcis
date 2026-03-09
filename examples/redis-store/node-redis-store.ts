/**
 * Redis Rate Limit Store for Shield (Node.js)
 * 
 * Provides distributed rate limiting using Redis as the backing store.
 * This enables consistent rate limiting across multiple server instances.
 * 
 * @example
 * import { RedisRateLimitStore } from './redis-store';
 * import shield from '@aspect.dev/shield-node';
 * 
 * const store = new RedisRateLimitStore({ host: 'localhost', port: 6379 });
 * app.use(shield({ rateLimit: { store } }));
 */

import Redis, { RedisOptions } from 'ioredis';

export interface RateLimitEntry {
  count: number;
  resetTime: number;
}

export interface RateLimitStore {
  get(key: string): Promise<RateLimitEntry | null>;
  set(key: string, entry: RateLimitEntry): Promise<void>;
  increment(key: string): Promise<number>;
}

export interface RedisStoreOptions extends RedisOptions {
  /** Prefix for all rate limit keys. Default: 'shield:ratelimit:' */
  keyPrefix?: string;
  /** TTL for keys in seconds. Default: 3600 (1 hour) */
  ttlSeconds?: number;
}

/**
 * Redis-backed rate limit store for distributed rate limiting.
 * 
 * Features:
 * - Atomic increment operations using Redis INCR
 * - Automatic key expiration using TTL
 * - Connection pooling via ioredis
 * - Graceful degradation on Redis errors
 */
export class RedisRateLimitStore implements RateLimitStore {
  private redis: Redis;
  private keyPrefix: string;
  private ttlSeconds: number;
  private closed: boolean = false;

  constructor(options: RedisStoreOptions = {}) {
    const { keyPrefix = 'shield:ratelimit:', ttlSeconds = 3600, ...redisOptions } = options;
    
    this.keyPrefix = keyPrefix;
    this.ttlSeconds = ttlSeconds;
    this.redis = new Redis(redisOptions);

    // Handle connection errors gracefully
    this.redis.on('error', (err) => {
      console.error('[Shield Redis Store] Connection error:', err.message);
    });

    this.redis.on('connect', () => {
      console.log('[Shield Redis Store] Connected to Redis');
    });
  }

  /**
   * Build the full Redis key with prefix
   */
  private buildKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  /**
   * Get rate limit entry for a key
   */
  async get(key: string): Promise<RateLimitEntry | null> {
    if (this.closed) return null;

    try {
      const fullKey = this.buildKey(key);
      const data = await this.redis.hgetall(fullKey);

      if (!data || !data.count || !data.resetTime) {
        return null;
      }

      return {
        count: parseInt(data.count, 10),
        resetTime: parseInt(data.resetTime, 10),
      };
    } catch (error) {
      console.error('[Shield Redis Store] Get error:', error);
      return null;
    }
  }

  /**
   * Set rate limit entry for a key
   */
  async set(key: string, entry: RateLimitEntry): Promise<void> {
    if (this.closed) return;

    try {
      const fullKey = this.buildKey(key);
      const pipeline = this.redis.pipeline();
      
      pipeline.hset(fullKey, {
        count: entry.count.toString(),
        resetTime: entry.resetTime.toString(),
      });
      
      // Set TTL based on reset time or default
      const ttl = Math.max(
        Math.ceil((entry.resetTime - Date.now()) / 1000),
        this.ttlSeconds
      );
      pipeline.expire(fullKey, ttl);
      
      await pipeline.exec();
    } catch (error) {
      console.error('[Shield Redis Store] Set error:', error);
    }
  }

  /**
   * Atomically increment the count for a key
   */
  async increment(key: string): Promise<number> {
    if (this.closed) return 1;

    try {
      const fullKey = this.buildKey(key);
      const newCount = await this.redis.hincrby(fullKey, 'count', 1);
      return newCount;
    } catch (error) {
      console.error('[Shield Redis Store] Increment error:', error);
      return 1; // Fail open
    }
  }

  /**
   * Close the Redis connection
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.redis.quit();
    console.log('[Shield Redis Store] Connection closed');
  }
}

/**
 * Create a Redis rate limit store with Lua script for atomic operations.
 * This version uses a Lua script for more efficient atomic increment-or-create.
 */
export class RedisRateLimitStoreAtomic implements RateLimitStore {
  private redis: Redis;
  private keyPrefix: string;
  private windowMs: number;
  private closed: boolean = false;

  // Lua script for atomic increment-or-create
  private static INCR_SCRIPT = `
    local key = KEYS[1]
    local window_ms = tonumber(ARGV[1])
    local now = tonumber(ARGV[2])
    
    local data = redis.call('HGETALL', key)
    local count = 0
    local reset_time = 0
    
    -- Parse existing data
    for i = 1, #data, 2 do
      if data[i] == 'count' then count = tonumber(data[i+1]) end
      if data[i] == 'resetTime' then reset_time = tonumber(data[i+1]) end
    end
    
    -- Check if window expired
    if reset_time == 0 or reset_time < now then
      count = 1
      reset_time = now + window_ms
      redis.call('HSET', key, 'count', count, 'resetTime', reset_time)
      redis.call('PEXPIRE', key, window_ms + 1000) -- Add 1s buffer
    else
      count = redis.call('HINCRBY', key, 'count', 1)
    end
    
    return {count, reset_time}
  `;

  constructor(
    redisOptions: RedisOptions = {},
    keyPrefix: string = 'shield:ratelimit:',
    windowMs: number = 60000
  ) {
    this.keyPrefix = keyPrefix;
    this.windowMs = windowMs;
    this.redis = new Redis(redisOptions);

    // Define the Lua script
    this.redis.defineCommand('shieldIncr', {
      numberOfKeys: 1,
      lua: RedisRateLimitStoreAtomic.INCR_SCRIPT,
    });

    this.redis.on('error', (err) => {
      console.error('[Shield Redis Store] Connection error:', err.message);
    });
  }

  private buildKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  async get(key: string): Promise<RateLimitEntry | null> {
    if (this.closed) return null;

    try {
      const fullKey = this.buildKey(key);
      const data = await this.redis.hgetall(fullKey);

      if (!data || !data.count || !data.resetTime) {
        return null;
      }

      const entry = {
        count: parseInt(data.count, 10),
        resetTime: parseInt(data.resetTime, 10),
      };

      // Check if expired
      if (entry.resetTime < Date.now()) {
        return null;
      }

      return entry;
    } catch (error) {
      console.error('[Shield Redis Store] Get error:', error);
      return null;
    }
  }

  async set(key: string, entry: RateLimitEntry): Promise<void> {
    if (this.closed) return;

    try {
      const fullKey = this.buildKey(key);
      const pipeline = this.redis.pipeline();
      
      pipeline.hset(fullKey, {
        count: entry.count.toString(),
        resetTime: entry.resetTime.toString(),
      });
      
      const ttl = Math.max(entry.resetTime - Date.now(), this.windowMs);
      pipeline.pexpire(fullKey, ttl + 1000); // Add 1s buffer
      
      await pipeline.exec();
    } catch (error) {
      console.error('[Shield Redis Store] Set error:', error);
    }
  }

  async increment(key: string): Promise<number> {
    if (this.closed) return 1;

    try {
      const fullKey = this.buildKey(key);
      // @ts-expect-error - shieldIncr is dynamically defined
      const [count] = await this.redis.shieldIncr(
        fullKey,
        this.windowMs,
        Date.now()
      ) as [number, number];
      return count;
    } catch (error) {
      console.error('[Shield Redis Store] Increment error:', error);
      return 1; // Fail open
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.redis.quit();
  }
}

// Re-export types for convenience
export type { Redis, RedisOptions };
