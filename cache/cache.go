package cache

import (
	"errors"
	"sync"
	"sync/atomic"
)

var (
	// ErrCacheNotFound error.
	ErrCacheNotFound = errors.New("cache not found")
	// ErrCacheExpired error.
	ErrCacheExpired = errors.New("cache expired")
)

// Cache uses SyncUInt64Map with radical eviction strategy
// Instead of evicting one by one, we evict entire segments at once!
type Cache struct {
	data          *SyncUInt64Map[any]
	maxSize       int64
	evictMu       sync.Mutex    // Serialize evictions
	evictionCount atomic.Uint64 // Track evictions to rotate which segment to clear
}

// NewCache creates a cache with radical eviction
func New(size int) *Cache {
	if size < 1 {
		size = 1
	}

	// Use optimal bucket sizing for SyncUInt64Map
	var power uint
	switch {
	case size <= 1024:
		power = 8 // 256 buckets
	case size <= 10000:
		power = 10 // 1K buckets
	case size <= 100000:
		power = 12 // 4K buckets
	case size <= 500000:
		power = 14 // 16K buckets
	default:
		power = 16 // 64K buckets for 1M+ entries
	}

	return &Cache{
		data:    NewSyncUInt64Map[any](power),
		maxSize: int64(size),
	}
}

// Get retrieves a value - uses SyncUInt64Map's excellent performance
func (c *Cache) Get(key uint64) (any, bool) {
	return c.data.Get(key)
}

// Add adds an item with radical eviction if needed
func (c *Cache) Add(key uint64, value any) {
	// Check if we need to make room first
	currentSize := c.data.Len()
	if currentSize >= c.maxSize {
		// Preemptively evict if at capacity
		c.radicalEvict()
	}

	// Add the item
	c.data.Set(key, value)

	// Double-check size after adding in case of race
	newSize := c.data.Len()
	if newSize > c.maxSize {
		c.radicalEvict()
	}
}

// radicalEvict - the RADICAL approach: clear entire segments!
func (c *Cache) radicalEvict() {
	// Use mutex to serialize evictions
	c.evictMu.Lock()
	defer c.evictMu.Unlock()

	// Re-check size after acquiring lock
	currentSize := c.data.Len()
	if currentSize <= c.maxSize {
		return
	}

	// For small caches, use targeted eviction
	if c.maxSize < 100 {
		toEvict := int(currentSize - c.maxSize + 10) // Add small buffer
		keys := c.data.RandomSample(toEvict * 2)
		for i, key := range keys {
			if i >= toEvict {
				break
			}
			c.data.Del(key)
		}
		return
	}

	// More aggressive eviction to prevent overshoot
	// We want to get well below maxSize to avoid constant eviction
	targetSize := c.maxSize * 8 / 10 // Target 80% of max size
	toEvict := currentSize - targetSize

	// Calculate percentage to evict
	percentToEvict := float64(toEvict) / float64(currentSize)

	// Evict based on percentage needed
	switch {
	case percentToEvict > 0.5:
		// Clear 60% for heavy eviction
		c.clearSegments(60)
	case percentToEvict > 0.3:
		// Clear 40% of segments
		c.clearSegments(40)
	case percentToEvict > 0.2:
		// Clear 25% of segments
		c.clearSegments(25)
	case percentToEvict > 0.1:
		// Clear 15% of segments
		c.clearSegments(15)
	default:
		// Clear 10% minimum
		c.clearSegments(10)
	}
}

// clearSegments clears a percentage of segments
func (c *Cache) clearSegments(percent int) {
	// Get segments to clear based on rotation
	segmentCount := c.data.SegmentCount()
	segmentsToClear := (segmentCount * percent) / 100
	if segmentsToClear < 1 {
		segmentsToClear = 1
	}

	// Rotate which segments we clear to be fair
	startSegment := c.evictionCount.Add(1) % uint64(segmentCount)

	for i := 0; i < segmentsToClear; i++ {
		segmentIndex := (startSegment + uint64(i)) % uint64(segmentCount)
		c.data.ClearSegment(int(segmentIndex))
	}
}

// Remove removes an item
func (c *Cache) Remove(key uint64) {
	c.data.Del(key)
}

// Len returns current size
func (c *Cache) Len() int {
	return int(c.data.Len())
}

// Stop cleanup
func (c *Cache) Stop() {
	c.data.Stop()
}
