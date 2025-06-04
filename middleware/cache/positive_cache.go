package cache

import (
	"time"

	"github.com/semihalev/sdns/cache"
)

// PositiveCache handles successful DNS responses
type PositiveCache struct {
	cache   *cache.Cache
	ttl     TTLManager
	metrics *CacheMetrics
}

// NewPositiveCache creates a new positive cache
func NewPositiveCache(size int, minTTL, maxTTL time.Duration, metrics *CacheMetrics) *PositiveCache {
	return &PositiveCache{
		cache:   cache.New(size),
		ttl:     NewTTLManager(minTTL, maxTTL),
		metrics: metrics,
	}
}

// Get retrieves an entry from the positive cache
func (pc *PositiveCache) Get(key uint64) (*CacheEntry, bool) {
	v, ok := pc.cache.Get(key)
	if !ok {
		pc.metrics.Miss()
		return nil, false
	}

	entry := v.(*CacheEntry)
	if entry.IsExpired() {
		pc.cache.Remove(key)
		pc.metrics.Miss()
		return nil, false
	}

	pc.metrics.Hit()
	return entry, true
}

// Set stores an entry in the positive cache
func (pc *PositiveCache) Set(key uint64, entry *CacheEntry) {
	pc.cache.Add(key, entry)
}

// Remove deletes an entry from the positive cache
func (pc *PositiveCache) Remove(key uint64) {
	pc.cache.Remove(key)
}

// Len returns the number of entries in the cache
func (pc *PositiveCache) Len() int {
	return pc.cache.Len()
}
