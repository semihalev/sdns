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

	// Bucket sizing: more buckets = less contention, better concurrency
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

// evict: random sampling strategy avoids full scan, O(evictions) not O(size)
func (c *Cache) evict() {
	// Run eviction in a loop until we're under the limit
	// This handles cases where items are being added concurrently
	for {
		currentSize := c.data.Len()
		if currentSize <= int64(c.maxSize) {
			return // We're under the limit
		}

		// Batch eviction: 5% minimum reduces eviction frequency, amortizes cost
		overhead := int(currentSize - int64(c.maxSize))
		evictBatch := overhead
		if evictBatch < c.maxSize/20 { // Minimum 5% of maxSize
			evictBatch = c.maxSize / 20
		}
		if evictBatch < 1 {
			evictBatch = 1
		}

		// Small caches: iteration beats random sampling overhead
		if c.maxSize < 100 || evictBatch < 10 {
			evicted := c.evictSimple(evictBatch)
			if evicted == 0 {
				break
			}
		} else {
			// Large caches: random sampling scales better than iteration
			evicted := c.evictRandomSample(evictBatch)
			if evicted == 0 {
				break
			}
		}

		// For small caches, one iteration is enough
		if c.maxSize < 100 {
			break
		}
	}
}

// evictSimple uses simple iteration for small caches
// Returns the number of entries actually evicted
func (c *Cache) evictSimple(targetEvictions int) int {
	evictBuf := make([]uint64, 0, targetEvictions)
	collected := 0

	c.data.ForEach(func(key uint64, _ any) bool {
		if collected >= targetEvictions {
			return false
		}
		evictBuf = append(evictBuf, key)
		collected++
		return true
	})

	// Delete the collected keys
	evicted := 0
	for _, key := range evictBuf {
		if c.data.Del(key) {
			evicted++
		}
	}

	return evicted
}

// evictRandomSample efficiently evicts a random sample of entries
// Returns the number of entries actually evicted
func (c *Cache) evictRandomSample(targetEvictions int) int {
	// Get a random sample of keys to evict
	keys := c.data.RandomSample(targetEvictions)

	// Delete the sampled keys
	evicted := 0
	for _, key := range keys {
		if c.data.Del(key) {
			evicted++
		}
	}

	return evicted
}
