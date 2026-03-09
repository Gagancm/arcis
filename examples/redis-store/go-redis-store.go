/*
Package redisstore provides a Redis-backed rate limit store for Shield.

This enables distributed rate limiting across multiple server instances.

Usage:

	import (
		"github.com/aspect.dev/shield-go"
		redisstore "github.com/aspect.dev/shield-go/examples/redis-store"
		"github.com/redis/go-redis/v9"
	)

	func main() {
		rdb := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		})

		store := redisstore.New(rdb, redisstore.Options{
			KeyPrefix: "shield:ratelimit:",
			WindowMs:  60000,
		})
		defer store.Close()

		s := shield.NewWithConfig(shield.Config{
			RateLimit:    true,
			RateLimitMax: 100,
		})
		s.SetRateLimitStore(store)

		http.Handle("/", s.Handler(myHandler))
		http.ListenAndServe(":8080", nil)
	}
*/
package redisstore

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimitEntry represents a rate limit entry.
type RateLimitEntry struct {
	Count     int
	ResetTime time.Time
}

// Store defines the interface for rate limit stores.
type Store interface {
	Get(ctx context.Context, key string) (*RateLimitEntry, error)
	Set(ctx context.Context, key string, entry *RateLimitEntry) error
	Increment(ctx context.Context, key string) (int, error)
	Close() error
}

// Options configures the Redis rate limit store.
type Options struct {
	// KeyPrefix is the prefix for all rate limit keys.
	// Default: "shield:ratelimit:"
	KeyPrefix string

	// WindowMs is the rate limit window in milliseconds.
	// Used for calculating TTL on keys.
	// Default: 60000 (1 minute)
	WindowMs int

	// TTLBuffer adds extra time to key TTL to prevent edge cases.
	// Default: 1 second
	TTLBuffer time.Duration
}

// DefaultOptions returns sensible default options.
func DefaultOptions() Options {
	return Options{
		KeyPrefix: "shield:ratelimit:",
		WindowMs:  60000,
		TTLBuffer: time.Second,
	}
}

// RedisStore implements Store using Redis.
type RedisStore struct {
	client    *redis.Client
	opts      Options
	closed    bool
	incrCmd   *redis.Script
}

// Lua script for atomic increment-or-create operation.
// This ensures race-condition-free rate limiting.
var incrScript = redis.NewScript(`
	local key = KEYS[1]
	local window_ms = tonumber(ARGV[1])
	local now = tonumber(ARGV[2])
	
	local count = redis.call('HGET', key, 'count')
	local reset_time = redis.call('HGET', key, 'resetTime')
	
	-- Convert to numbers (nil becomes 0)
	count = tonumber(count) or 0
	reset_time = tonumber(reset_time) or 0
	
	-- Check if window expired or new key
	if reset_time == 0 or reset_time < now then
		count = 1
		reset_time = now + window_ms
		redis.call('HSET', key, 'count', count, 'resetTime', reset_time)
		redis.call('PEXPIRE', key, window_ms + 1000)
	else
		count = redis.call('HINCRBY', key, 'count', 1)
	end
	
	return {count, reset_time}
`)

// New creates a new Redis rate limit store.
func New(client *redis.Client, opts Options) *RedisStore {
	if opts.KeyPrefix == "" {
		opts.KeyPrefix = "shield:ratelimit:"
	}
	if opts.WindowMs == 0 {
		opts.WindowMs = 60000
	}
	if opts.TTLBuffer == 0 {
		opts.TTLBuffer = time.Second
	}

	return &RedisStore{
		client:  client,
		opts:    opts,
		incrCmd: incrScript,
	}
}

// NewWithDefaults creates a new Redis rate limit store with default options.
func NewWithDefaults(client *redis.Client) *RedisStore {
	return New(client, DefaultOptions())
}

// buildKey creates the full Redis key with prefix.
func (s *RedisStore) buildKey(key string) string {
	return s.opts.KeyPrefix + key
}

// Get retrieves a rate limit entry for the given key.
func (s *RedisStore) Get(ctx context.Context, key string) (*RateLimitEntry, error) {
	if s.closed {
		return nil, fmt.Errorf("store is closed")
	}

	fullKey := s.buildKey(key)
	result, err := s.client.HGetAll(ctx, fullKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis hgetall error: %w", err)
	}

	if len(result) == 0 {
		return nil, nil
	}

	countStr, ok := result["count"]
	if !ok {
		return nil, nil
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return nil, fmt.Errorf("invalid count value: %w", err)
	}

	resetTimeStr, ok := result["resetTime"]
	if !ok {
		return nil, nil
	}
	resetTimeMs, err := strconv.ParseInt(resetTimeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid resetTime value: %w", err)
	}

	entry := &RateLimitEntry{
		Count:     count,
		ResetTime: time.UnixMilli(resetTimeMs),
	}

	// Check if expired
	if entry.ResetTime.Before(time.Now()) {
		return nil, nil
	}

	return entry, nil
}

// Set stores a rate limit entry for the given key.
func (s *RedisStore) Set(ctx context.Context, key string, entry *RateLimitEntry) error {
	if s.closed {
		return fmt.Errorf("store is closed")
	}

	fullKey := s.buildKey(key)
	pipe := s.client.Pipeline()

	pipe.HSet(ctx, fullKey,
		"count", strconv.Itoa(entry.Count),
		"resetTime", strconv.FormatInt(entry.ResetTime.UnixMilli(), 10),
	)

	// Calculate TTL
	ttl := time.Until(entry.ResetTime) + s.opts.TTLBuffer
	if ttl < time.Second {
		ttl = time.Duration(s.opts.WindowMs)*time.Millisecond + s.opts.TTLBuffer
	}
	pipe.Expire(ctx, fullKey, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis pipeline error: %w", err)
	}

	return nil
}

// Increment atomically increments the count for a key.
// If the key doesn't exist or is expired, it creates a new entry.
func (s *RedisStore) Increment(ctx context.Context, key string) (int, error) {
	if s.closed {
		return 1, fmt.Errorf("store is closed")
	}

	fullKey := s.buildKey(key)
	now := time.Now().UnixMilli()

	result, err := s.incrCmd.Run(ctx, s.client, []string{fullKey}, s.opts.WindowMs, now).Slice()
	if err != nil {
		return 1, fmt.Errorf("redis script error: %w", err)
	}

	if len(result) < 1 {
		return 1, fmt.Errorf("unexpected script result")
	}

	count, ok := result[0].(int64)
	if !ok {
		return 1, fmt.Errorf("unexpected count type")
	}

	return int(count), nil
}

// Close closes the store. After calling Close, all operations will fail.
// Note: This does NOT close the underlying Redis client, as it may be shared.
func (s *RedisStore) Close() error {
	s.closed = true
	return nil
}

// CloseWithClient closes the store and the underlying Redis client.
func (s *RedisStore) CloseWithClient() error {
	s.closed = true
	return s.client.Close()
}

// Ping checks if Redis is reachable.
func (s *RedisStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// Stats returns basic statistics about the store.
type Stats struct {
	KeyCount int64
	MemUsage int64
}

// GetStats returns statistics about rate limit keys.
func (s *RedisStore) GetStats(ctx context.Context) (*Stats, error) {
	if s.closed {
		return nil, fmt.Errorf("store is closed")
	}

	// Count keys with our prefix
	pattern := s.opts.KeyPrefix + "*"
	var cursor uint64
	var keyCount int64

	for {
		keys, nextCursor, err := s.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("redis scan error: %w", err)
		}
		keyCount += int64(len(keys))
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return &Stats{
		KeyCount: keyCount,
	}, nil
}
