/**
 * @module @arcis/node/stores/redis
 * Redis rate limit store
 * 
 * Note: This is a reference implementation. You'll need to install
 * the 'ioredis' or 'redis' package and pass your client instance.
 */

import type { RateLimitStore, RateLimitEntry } from '../core/types';
import { RATE_LIMIT } from '../core/constants';

/** Generic Redis client interface (works with ioredis, redis, etc.) */
export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number): Promise<unknown>;
  setex(key: string, seconds: number, value: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  decr(key: string): Promise<number>;
  del(key: string): Promise<number>;
  ttl(key: string): Promise<number>;
  quit?(): Promise<unknown>;
  disconnect?(): Promise<unknown>;
}

export interface RedisStoreOptions {
  /** Redis client instance */
  client: RedisClientLike;
  /** Key prefix. Default: 'arcis:rl:' */
  prefix?: string;
  /** Window size in milliseconds. Default: 60000 */
  windowMs?: number;
}

/**
 * Redis rate limit store for distributed deployments.
 * 
 * @example
 * import Redis from 'ioredis';
 * 
 * const redis = new Redis();
 * const store = new RedisStore({ client: redis });
 * const limiter = createRateLimiter({ store });
 * 
 * // Cleanup on shutdown
 * process.on('SIGTERM', async () => {
 *   await store.close();
 * });
 */
export class RedisStore implements RateLimitStore {
  private client: RedisClientLike;
  private prefix: string;
  private windowMs: number;
  private windowSec: number;

  constructor(options: RedisStoreOptions) {
    this.client = options.client;
    this.prefix = options.prefix ?? 'arcis:rl:';
    this.windowMs = options.windowMs ?? RATE_LIMIT.DEFAULT_WINDOW_MS;
    this.windowSec = Math.ceil(this.windowMs / 1000);
  }

  private getKey(key: string): string {
    return `${this.prefix}${key}`;
  }

  async get(key: string): Promise<RateLimitEntry | null> {
    const redisKey = this.getKey(key);
    
    const [countStr, ttl] = await Promise.all([
      this.client.get(redisKey),
      this.client.ttl(redisKey),
    ]);
    
    if (!countStr || ttl < 0) {
      return null;
    }
    
    return {
      count: parseInt(countStr, 10),
      resetTime: Date.now() + (ttl * 1000),
    };
  }

  async set(key: string, entry: RateLimitEntry): Promise<void> {
    const redisKey = this.getKey(key);
    const ttlSec = Math.ceil((entry.resetTime - Date.now()) / 1000);
    
    if (ttlSec > 0) {
      await this.client.setex(redisKey, ttlSec, entry.count.toString());
    }
  }

  async increment(key: string): Promise<number> {
    const redisKey = this.getKey(key);
    
    // INCR creates key with value 1 if it doesn't exist
    const count = await this.client.incr(redisKey);
    
    // Set expiry only on first increment (when count is 1)
    if (count === 1) {
      // Use EXPIRE to set TTL (setex would overwrite the value)
      await this.client.set(redisKey, count.toString(), 'EX', this.windowSec);
    }
    
    return count;
  }

  async decrement(key: string): Promise<void> {
    const redisKey = this.getKey(key);
    await this.client.decr(redisKey);
  }

  async reset(key: string): Promise<void> {
    const redisKey = this.getKey(key);
    await this.client.del(redisKey);
  }

  async close(): Promise<void> {
    // Don't close the client - it may be shared
    // The caller should manage the client lifecycle
  }
}

/**
 * Create a Redis store with the given options.
 * Convenience function for functional programming style.
 * 
 * @example
 * const store = createRedisStore({ client: redisClient });
 */
export function createRedisStore(options: RedisStoreOptions): RedisStore {
  return new RedisStore(options);
}
