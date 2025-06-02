// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"errors"
)

var (
	// ErrCacheNotFound error
	ErrCacheNotFound = errors.New("cache not found")
	// ErrCacheExpired error
	ErrCacheExpired = errors.New("cache expired")
)

// Cache is cache.
type Cache struct {
	data    *SyncUInt64Map[any]
	maxSize int
}

// New returns a new cache.
func New(size int) *Cache {
	if size < 1 {
		size = 1
	}

	// Calculate optimal bucket count based on cache size
	// For DNS cache, we want good distribution with minimal overhead
	var power uint
	switch {
	case size <= 1024:
		power = 8 // 256 buckets for tiny caches
	case size <= 10000:
		power = 10 // 1K buckets for small caches
	case size <= 100000:
		power = 12 // 4K buckets for medium caches
	case size <= 500000:
		power = 14 // 16K buckets for large caches (default SDNS size)
	default:
		power = 16 // 64K buckets for very large caches
	}

	return &Cache{
		data:    NewSyncUInt64Map[any](power),
		maxSize: size,
	}
}

// Get looks up element index under key.
func (c *Cache) Get(key uint64) (any, bool) {
	return c.data.Get(key)
}

// Add adds a new element to the cache. If the element already exists it is overwritten.
func (c *Cache) Add(key uint64, el any) {
	// Set the value first
	c.data.Set(key, el)

	// Check if we exceeded the limit after adding
	currentSize := c.data.Len()
	if currentSize > int64(c.maxSize) {
		// Need to evict some entries
		c.evict()
	}
}

// Remove removes the element indexed with key.
func (c *Cache) Remove(key uint64) {
	c.data.Del(key)
}

// Len returns the number of elements in the cache.
func (c *Cache) Len() int {
	return int(c.data.Len())
}

// evict removes entries when cache is full
// Uses sampled eviction - randomly samples entries and removes some of them
func (c *Cache) evict() {
	// Run eviction in a loop until we're under the limit
	// This handles cases where items are being added concurrently
	for {
		currentSize := c.data.Len()
		if currentSize <= int64(c.maxSize) {
			return // We're under the limit
		}

		// Calculate how many entries to evict
		overhead := int(currentSize - int64(c.maxSize))
		evictBatch := overhead
		if evictBatch < c.maxSize/20 { // At least 5%
			evictBatch = c.maxSize / 20
		}
		if evictBatch < 1 {
			evictBatch = 1
		}

		// Collect keys to evict
		// Use a local buffer to avoid race conditions
		evictBuf := make([]uint64, 0, evictBatch)
		collected := 0
		c.data.ForEach(func(key uint64, _ any) bool {
			if collected >= evictBatch {
				return false
			}
			evictBuf = append(evictBuf, key)
			collected++
			return true
		})

		// If we couldn't collect any keys, break to avoid infinite loop
		if len(evictBuf) == 0 {
			break
		}

		// Delete the collected keys
		for _, key := range evictBuf {
			c.data.Del(key)
		}

		// For small caches, one iteration is enough
		if c.maxSize < 100 {
			break
		}
	}
}
