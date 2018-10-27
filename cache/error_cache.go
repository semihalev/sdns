package cache

import (
	"time"
)

// ErrorCache type
type ErrorCache struct {
	shards [shardSize]*shard
	ttl    uint32
}

// NewErrorCache return new cache
func NewErrorCache(size int, ttl uint32) *ErrorCache {
	ssize := size / shardSize
	if ssize < 4 {
		ssize = 4
	}

	c := &ErrorCache{
		ttl: ttl,
	}

	// Initialize all the shards
	for i := 0; i < shardSize; i++ {
		c.shards[i] = newShard(ssize)
	}

	return c
}

// Get returns the entry for a key or an error
func (c *ErrorCache) Get(key uint64) error {
	shard := key & (shardSize - 1)

	el, ok := c.shards[shard].Get(key)

	if !ok {
		return ErrCacheNotFound
	}

	t, ok := el.(time.Time)

	if !ok {
		return ErrCacheNotFound
	}

	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(t).Seconds())

	if elapsed >= c.ttl {
		c.Remove(key)
		return ErrCacheExpired
	}

	return nil
}

// Set sets a keys value to a error cache
func (c *ErrorCache) Set(key uint64) error {
	shard := key & (shardSize - 1)
	c.shards[shard].Set(key, WallClock.Now().Truncate(time.Second))

	return nil
}

// Remove removes an entry from the cache
func (c *ErrorCache) Remove(key uint64) {
	shard := key & (shardSize - 1)
	c.shards[shard].Remove(key)
}

// Len returns the caches length
func (c *ErrorCache) Len() int {
	l := 0
	for _, s := range c.shards {
		l += s.Len()
	}
	return l
}
