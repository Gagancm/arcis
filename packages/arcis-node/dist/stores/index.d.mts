import { g as RateLimitStore, R as RateLimitEntry } from '../types-D7WNLpcY.mjs';
import 'express';

/**
 * @module @arcis/node/stores/memory
 * In-memory rate limit store
 */

/**
 * In-memory rate limit store.
 * Suitable for single-instance deployments.
 * For distributed systems, use RedisStore or a custom store.
 *
 * @example
 * const store = new MemoryStore(60000); // 1 minute window
 * const limiter = createRateLimiter({ store });
 */
declare class MemoryStore implements RateLimitStore {
    private store;
    private cleanupInterval;
    private windowMs;
    constructor(windowMs?: number);
    /**
     * Start the cleanup interval to remove expired entries.
     */
    private startCleanup;
    get(key: string): Promise<RateLimitEntry | null>;
    set(key: string, entry: RateLimitEntry): Promise<void>;
    increment(key: string): Promise<number>;
    decrement(key: string): Promise<void>;
    reset(key: string): Promise<void>;
    close(): Promise<void>;
    /**
     * Get current store size (for monitoring).
     */
    get size(): number;
}

/**
 * @module @arcis/node/stores/redis
 * Redis rate limit store
 *
 * Note: This is a reference implementation. You'll need to install
 * the 'ioredis' or 'redis' package and pass your client instance.
 */

/** Generic Redis client interface (works with ioredis, redis, etc.) */
interface RedisClientLike {
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
interface RedisStoreOptions {
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
declare class RedisStore implements RateLimitStore {
    private client;
    private prefix;
    private windowMs;
    private windowSec;
    constructor(options: RedisStoreOptions);
    private getKey;
    get(key: string): Promise<RateLimitEntry | null>;
    set(key: string, entry: RateLimitEntry): Promise<void>;
    increment(key: string): Promise<number>;
    decrement(key: string): Promise<void>;
    reset(key: string): Promise<void>;
    close(): Promise<void>;
}
/**
 * Create a Redis store with the given options.
 * Convenience function for functional programming style.
 *
 * @example
 * const store = createRedisStore({ client: redisClient });
 */
declare function createRedisStore(options: RedisStoreOptions): RedisStore;

export { MemoryStore, type RedisClientLike, RedisStore, type RedisStoreOptions, createRedisStore };
