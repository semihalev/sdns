package cache

import (
	"errors"
)

var (
	// ErrCacheNotFound error.
	ErrCacheNotFound = errors.New("cache not found")
	// ErrCacheExpired error.
	ErrCacheExpired = errors.New("cache expired")
)

// Cache is cache.
type Cache struct {
	data           *SyncUInt64Map[any]
	maxSize        int
	stopCompaction chan struct{}
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

	c := &Cache{
		data:           NewSyncUInt64Map[any](power),
		maxSize:        size,
		stopCompaction: make(chan struct{}),
	}

	// No need for periodic compaction - the new map handles it internally

	return c
}

// (*Cache).Get get looks up element index under key.
func (c *Cache) Get(key uint64) (any, bool) {
	return c.data.Get(key)
}

// (*Cache).Add add adds a new element to the cache. If the element already exists it is overwritten.
func (c *Cache) Add(key uint64, el any) {
	// For small caches, check size before adding to prevent overshoot
	if c.maxSize < 10000 {
		currentSize := c.data.Len()
		if currentSize >= int64(c.maxSize) {
			c.evict()
		}
	}

	// Set the value
	c.data.Set(key, el)

	// Always check if we exceeded the limit after adding
	currentSize := c.data.Len()
	if currentSize > int64(c.maxSize) {
		// Need to evict some entries
		c.evict()
	}
}

// (*Cache).Remove remove removes the element indexed with key.
func (c *Cache) Remove(key uint64) {
	c.data.Del(key)
}

// (*Cache).Len len returns the number of elements in the cache.
func (c *Cache) Len() int {
	return int(c.data.Len())
}

// evict: random sampling strategy avoids full scan, O(evictions) not O(size)
func (c *Cache) evict() {
	// Run eviction in a loop until we're under the limit
	// This handles cases where items are being added concurrently
	maxAttempts := 10 // Prevent infinite loop
	attempts := 0

	for attempts < maxAttempts {
		currentSize := c.data.Len()
		if currentSize <= int64(c.maxSize) {
			return // We're under the limit
		}

		// Calculate eviction batch
		overhead := int(currentSize - int64(c.maxSize))

		// Evict just what we need plus a small buffer
		evictBatch := overhead + 10
		if evictBatch < 1 {
			evictBatch = 1
		}

		// For rate limiter caches under attack, use smaller batches
		if c.maxSize >= 10000 && c.maxSize <= 30000 {
			// This is likely the rate limiter cache (25,600 entries)
			// Use much smaller eviction batch to avoid CPU spikes
			evictBatch = overhead + 1
			if evictBatch > 100 {
				evictBatch = 100
			}
		}

		// Use simple eviction for smaller batches
		if evictBatch < 100 {
			evicted := c.evictSimple(evictBatch)
			if evicted == 0 {
				break
			}
		} else {
			// Only use random sampling for large batches
			evicted := c.evictRandomSample(evictBatch)
			if evicted == 0 {
				break
			}
		}

		attempts++

		// For small caches, one iteration is enough
		if c.maxSize < 100 {
			break
		}
	}
}

// evictSimple uses simple iteration for small caches
// Returns the number of entries actually evicted.
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

// evictRandomSample uses random sampling for large caches
// Efficiently evicts entries without iterating the entire map.
func (c *Cache) evictRandomSample(targetEvictions int) int {
	// Reduced oversampling to minimize CPU usage
	sampleSize := targetEvictions * 2 // 2x oversampling instead of 5x
	if sampleSize > 10000 {
		sampleSize = 10000 // Hard cap to prevent CPU spikes
	}
	if sampleSize < targetEvictions {
		sampleSize = targetEvictions
	}

	keys := c.data.RandomSample(sampleSize)

	// Delete keys until we've evicted enough
	evicted := 0
	for _, key := range keys {
		if evicted >= targetEvictions {
			break
		}
		if c.data.Del(key) {
			evicted++
		}
	}

	return evicted
}

// Stop stops the periodic compaction
func (c *Cache) Stop() {
	if c.stopCompaction != nil {
		close(c.stopCompaction)
	}
	if c.data != nil {
		c.data.Stop()
	}
}
