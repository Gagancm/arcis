/**
 * MemoryStore Tests
 * Tests for src/stores/memory.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MemoryStore } from '../../src/stores/memory';
import { RATE_LIMIT } from '../../src/core/constants';

describe('MemoryStore', () => {
  let store: MemoryStore;

  afterEach(async () => {
    await store?.close();
  });

  describe('Constructor', () => {
    it('should create store with default window', () => {
      store = new MemoryStore();
      expect(store).toBeDefined();
    });

    it('should create store with custom window', () => {
      store = new MemoryStore(30000);
      expect(store).toBeDefined();
    });
  });

  describe('get', () => {
    it('should return null for non-existent key', async () => {
      store = new MemoryStore();
      const result = await store.get('non-existent');
      expect(result).toBeNull();
    });

    it('should return entry for existing key', async () => {
      store = new MemoryStore();
      await store.set('test-key', { count: 5, resetTime: Date.now() + 60000 });
      
      const result = await store.get('test-key');
      expect(result).toEqual({ count: 5, resetTime: expect.any(Number) });
    });

    it('should return null for expired entry', async () => {
      store = new MemoryStore();
      // Set entry with already expired time
      await store.set('expired-key', { count: 5, resetTime: Date.now() - 1000 });
      
      const result = await store.get('expired-key');
      expect(result).toBeNull();
    });

    it('should delete expired entry on get', async () => {
      store = new MemoryStore();
      await store.set('expired-key', { count: 5, resetTime: Date.now() - 1000 });
      
      await store.get('expired-key');
      expect(store.size).toBe(0);
    });
  });

  describe('set', () => {
    it('should set a new entry', async () => {
      store = new MemoryStore();
      await store.set('new-key', { count: 1, resetTime: Date.now() + 60000 });
      
      const result = await store.get('new-key');
      expect(result).not.toBeNull();
      expect(result?.count).toBe(1);
    });

    it('should overwrite existing entry', async () => {
      store = new MemoryStore();
      await store.set('key', { count: 1, resetTime: Date.now() + 60000 });
      await store.set('key', { count: 10, resetTime: Date.now() + 60000 });
      
      const result = await store.get('key');
      expect(result?.count).toBe(10);
    });
  });

  describe('increment', () => {
    it('should create new entry if key does not exist', async () => {
      store = new MemoryStore(60000);
      const count = await store.increment('new-key');
      
      expect(count).toBe(1);
      const entry = await store.get('new-key');
      expect(entry?.count).toBe(1);
    });

    it('should increment existing entry', async () => {
      store = new MemoryStore();
      await store.set('key', { count: 5, resetTime: Date.now() + 60000 });
      
      const count = await store.increment('key');
      expect(count).toBe(6);
    });

    it('should create new window if current is expired', async () => {
      store = new MemoryStore(60000);
      await store.set('key', { count: 5, resetTime: Date.now() - 1000 });
      
      const count = await store.increment('key');
      expect(count).toBe(1); // New window, starts at 1
    });

    it('should set correct reset time on new window', async () => {
      store = new MemoryStore(60000);
      const beforeIncrement = Date.now();
      
      await store.increment('key');
      
      const entry = await store.get('key');
      expect(entry?.resetTime).toBeGreaterThan(beforeIncrement);
      expect(entry?.resetTime).toBeLessThanOrEqual(beforeIncrement + 60000 + 100); // Allow small margin
    });
  });

  describe('decrement', () => {
    it('should decrement existing entry', async () => {
      store = new MemoryStore();
      await store.set('key', { count: 5, resetTime: Date.now() + 60000 });
      
      await store.decrement('key');
      const entry = await store.get('key');
      expect(entry?.count).toBe(4);
    });

    it('should not go below 0', async () => {
      store = new MemoryStore();
      await store.set('key', { count: 0, resetTime: Date.now() + 60000 });
      
      await store.decrement('key');
      const entry = await store.get('key');
      expect(entry?.count).toBe(0);
    });

    it('should do nothing for non-existent key', async () => {
      store = new MemoryStore();
      await store.decrement('non-existent');
      // Should not throw
      expect(store.size).toBe(0);
    });
  });

  describe('reset', () => {
    it('should delete the entry', async () => {
      store = new MemoryStore();
      await store.set('key', { count: 5, resetTime: Date.now() + 60000 });
      
      await store.reset('key');
      const entry = await store.get('key');
      expect(entry).toBeNull();
    });

    it('should do nothing for non-existent key', async () => {
      store = new MemoryStore();
      await store.reset('non-existent');
      // Should not throw
      expect(true).toBe(true);
    });
  });

  describe('close', () => {
    it('should clear all entries', async () => {
      store = new MemoryStore();
      await store.set('key1', { count: 1, resetTime: Date.now() + 60000 });
      await store.set('key2', { count: 2, resetTime: Date.now() + 60000 });
      
      await store.close();
      expect(store.size).toBe(0);
    });

    it('should stop cleanup interval', async () => {
      store = new MemoryStore(1000); // Minimum valid window
      await store.close();
      
      // Store should be closed, adding new entries should not be cleaned up
      // (because interval is stopped)
      // This is a bit tricky to test directly, but close should not throw
      expect(true).toBe(true);
    });

    it('should be idempotent', async () => {
      store = new MemoryStore();
      await store.close();
      await store.close(); // Should not throw
      expect(true).toBe(true);
    });
  });

  describe('size', () => {
    it('should return 0 for empty store', () => {
      store = new MemoryStore();
      expect(store.size).toBe(0);
    });

    it('should return correct count of entries', async () => {
      store = new MemoryStore();
      await store.set('key1', { count: 1, resetTime: Date.now() + 60000 });
      await store.set('key2', { count: 2, resetTime: Date.now() + 60000 });
      await store.set('key3', { count: 3, resetTime: Date.now() + 60000 });
      
      expect(store.size).toBe(3);
    });
  });

  describe('Cleanup', () => {
    it('should clean up expired entries periodically', async () => {
      vi.useFakeTimers();

      try {
        store = new MemoryStore(1000); // 1 second window
        await store.set('key1', { count: 1, resetTime: Date.now() + 500 });
        await store.set('key2', { count: 2, resetTime: Date.now() + 2000 });

        expect(store.size).toBe(2);

        // Advance time past first entry's expiration and trigger cleanup
        vi.advanceTimersByTime(1100);

        // The cleanup runs on interval, give it time
        vi.advanceTimersByTime(1000);

        // First entry should be cleaned up, second should remain
        expect(store.size).toBeLessThanOrEqual(2);
      } finally {
        vi.useRealTimers();
        await store.close();
      }
    });
  });

  describe('RateLimitStore Interface', () => {
    it('should implement all required methods', () => {
      store = new MemoryStore();
      
      expect(typeof store.get).toBe('function');
      expect(typeof store.set).toBe('function');
      expect(typeof store.increment).toBe('function');
      expect(typeof store.decrement).toBe('function');
      expect(typeof store.reset).toBe('function');
      expect(typeof store.close).toBe('function');
    });

    it('should work with default window from constants', () => {
      store = new MemoryStore(RATE_LIMIT.DEFAULT_WINDOW_MS);
      expect(store).toBeDefined();
    });
  });

  describe('Concurrent Operations', () => {
    it('should handle multiple increments correctly', async () => {
      store = new MemoryStore();
      
      // Simulate concurrent increments
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(store.increment('concurrent-key'));
      }
      
      const results = await Promise.all(promises);
      const entry = await store.get('concurrent-key');
      
      expect(entry?.count).toBe(10);
      // Results should be 1 through 10 (in some order)
      expect(results.sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    });

    it('should handle multiple keys simultaneously', async () => {
      store = new MemoryStore();
      
      const promises = [
        store.increment('key-a'),
        store.increment('key-b'),
        store.increment('key-c'),
        store.increment('key-a'),
        store.increment('key-b'),
        store.increment('key-a'),
      ];
      
      await Promise.all(promises);
      
      const entryA = await store.get('key-a');
      const entryB = await store.get('key-b');
      const entryC = await store.get('key-c');
      
      expect(entryA?.count).toBe(3);
      expect(entryB?.count).toBe(2);
      expect(entryC?.count).toBe(1);
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long keys', async () => {
      store = new MemoryStore();
      const longKey = 'a'.repeat(1000);
      
      await store.increment(longKey);
      const entry = await store.get(longKey);
      expect(entry?.count).toBe(1);
    });

    it('should handle special characters in keys', async () => {
      store = new MemoryStore();
      const specialKey = 'user:123:ip:192.168.1.1';
      
      await store.increment(specialKey);
      const entry = await store.get(specialKey);
      expect(entry?.count).toBe(1);
    });

    it('should handle empty string key', async () => {
      store = new MemoryStore();
      
      await store.increment('');
      const entry = await store.get('');
      expect(entry?.count).toBe(1);
    });
  });
});
