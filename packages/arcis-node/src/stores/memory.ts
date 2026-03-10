/**
 * @module @arcis/node/stores/memory
 * In-memory rate limit store
 */

import type { RateLimitStore, RateLimitEntry } from '../core/types';
import { RATE_LIMIT } from '../core/constants';

/**
 * In-memory rate limit store.
 * Suitable for single-instance deployments.
 * For distributed systems, use RedisStore or a custom store.
 * 
 * @example
 * const store = new MemoryStore(60000); // 1 minute window
 * const limiter = createRateLimiter({ store });
 */
export class MemoryStore implements RateLimitStore {
  private store: Map<string, RateLimitEntry> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private windowMs: number;

  constructor(windowMs: number = RATE_LIMIT.DEFAULT_WINDOW_MS) {
    this.windowMs = windowMs;
    this.startCleanup();
  }

  /**
   * Start the cleanup interval to remove expired entries.
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store.entries()) {
        if (entry.resetTime < now) {
          this.store.delete(key);
        }
      }
    }, this.windowMs);

    // Prevent interval from keeping the process alive
    if (typeof this.cleanupInterval.unref === 'function') {
      this.cleanupInterval.unref();
    }
  }

  async get(key: string): Promise<RateLimitEntry | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    
    // Check if expired
    if (entry.resetTime < Date.now()) {
      this.store.delete(key);
      return null;
    }
    
    return entry;
  }

  async set(key: string, entry: RateLimitEntry): Promise<void> {
    this.store.set(key, entry);
  }

  async increment(key: string): Promise<number> {
    const now = Date.now();
    const entry = this.store.get(key);
    
    if (!entry || entry.resetTime < now) {
      // Start new window
      this.store.set(key, { count: 1, resetTime: now + this.windowMs });
      return 1;
    }
    
    entry.count++;
    return entry.count;
  }

  async decrement(key: string): Promise<void> {
    const entry = this.store.get(key);
    if (entry && entry.count > 0) {
      entry.count--;
    }
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }

  async close(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }

  /**
   * Get current store size (for monitoring).
   */
  get size(): number {
    return this.store.size;
  }
}
