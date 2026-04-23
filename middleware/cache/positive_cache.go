package cache

import (
	"time"

	"github.com/semihalev/sdns/cache"
)

// PositiveCache handles successful DNS responses.
type PositiveCache struct {
	cache   *cache.Cache
	ttl     TTLManager
	metrics *CacheMetrics
}

// NewPositiveCache creates a new positive cache.
func NewPositiveCache(size int, minTTL, maxTTL time.Duration, metrics *CacheMetrics) *PositiveCache {
	return &PositiveCache{
		cache:   cache.New(size),
		ttl:     NewTTLManager(minTTL, maxTTL),
		metrics: metrics,
	}
}

// (*PositiveCache).Get get retrieves an entry from the positive cache.
// Hit/Miss metrics are NOT recorded here — checkCache consults both
// positive and negative caches per request and records the aggregate
// result once, so pushing metrics in here would double-count both
// sides of a single miss.
func (pc *PositiveCache) Get(key uint64) (*CacheEntry, bool) {
	v, ok := pc.cache.Get(key)
	if !ok {
		return nil, false
	}

	entry := v.(*CacheEntry)
	if entry.IsExpired() {
		pc.cache.Remove(key)
		return nil, false
	}

	return entry, true
}

// (*PositiveCache).Set set stores an entry in the positive cache.
func (pc *PositiveCache) Set(key uint64, entry *CacheEntry) {
	pc.cache.Add(key, entry)
}

// (*PositiveCache).Remove remove deletes an entry from the positive cache.
func (pc *PositiveCache) Remove(key uint64) {
	pc.cache.Remove(key)
}

// (*PositiveCache).Len len returns the number of entries in the cache.
func (pc *PositiveCache) Len() int {
	return pc.cache.Len()
}
