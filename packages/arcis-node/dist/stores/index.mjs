// src/core/constants.ts
var RATE_LIMIT = {
  /** Default window size (1 minute) */
  DEFAULT_WINDOW_MS: 6e4};

// src/stores/memory.ts
var MemoryStore = class {
  constructor(windowMs = RATE_LIMIT.DEFAULT_WINDOW_MS) {
    this.store = /* @__PURE__ */ new Map();
    this.cleanupInterval = null;
    this.windowMs = windowMs;
    this.startCleanup();
  }
  /**
   * Start the cleanup interval to remove expired entries.
   */
  startCleanup() {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store.entries()) {
        if (entry.resetTime < now) {
          this.store.delete(key);
        }
      }
    }, this.windowMs);
    if (typeof this.cleanupInterval.unref === "function") {
      this.cleanupInterval.unref();
    }
  }
  async get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.resetTime < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry;
  }
  async set(key, entry) {
    this.store.set(key, entry);
  }
  async increment(key) {
    const now = Date.now();
    const entry = this.store.get(key);
    if (!entry || entry.resetTime < now) {
      this.store.set(key, { count: 1, resetTime: now + this.windowMs });
      return 1;
    }
    entry.count++;
    return entry.count;
  }
  async decrement(key) {
    const entry = this.store.get(key);
    if (entry && entry.count > 0) {
      entry.count--;
    }
  }
  async reset(key) {
    this.store.delete(key);
  }
  async close() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }
  /**
   * Get current store size (for monitoring).
   */
  get size() {
    return this.store.size;
  }
};

// src/stores/redis.ts
var RedisStore = class {
  constructor(options) {
    this.client = options.client;
    this.prefix = options.prefix ?? "arcis:rl:";
    this.windowMs = options.windowMs ?? RATE_LIMIT.DEFAULT_WINDOW_MS;
    this.windowSec = Math.ceil(this.windowMs / 1e3);
  }
  getKey(key) {
    return `${this.prefix}${key}`;
  }
  async get(key) {
    const redisKey = this.getKey(key);
    const [countStr, ttl] = await Promise.all([
      this.client.get(redisKey),
      this.client.ttl(redisKey)
    ]);
    if (!countStr || ttl < 0) {
      return null;
    }
    return {
      count: parseInt(countStr, 10),
      resetTime: Date.now() + ttl * 1e3
    };
  }
  async set(key, entry) {
    const redisKey = this.getKey(key);
    const ttlSec = Math.ceil((entry.resetTime - Date.now()) / 1e3);
    if (ttlSec > 0) {
      await this.client.setex(redisKey, ttlSec, entry.count.toString());
    }
  }
  async increment(key) {
    const redisKey = this.getKey(key);
    const count = await this.client.incr(redisKey);
    if (count === 1) {
      await this.client.set(redisKey, count.toString(), "EX", this.windowSec);
    }
    return count;
  }
  async decrement(key) {
    const redisKey = this.getKey(key);
    await this.client.decr(redisKey);
  }
  async reset(key) {
    const redisKey = this.getKey(key);
    await this.client.del(redisKey);
  }
  async close() {
  }
};
function createRedisStore(options) {
  return new RedisStore(options);
}

export { MemoryStore, RedisStore, createRedisStore };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map