package cache

import (
	"time"

	"github.com/semihalev/sdns/cache"
)

// NegativeCache handles error DNS responses
type NegativeCache struct {
	cache   *cache.Cache
	ttl     TTLManager
	metrics *CacheMetrics
}

// NewNegativeCache creates a new negative cache
func NewNegativeCache(size int, minTTL, maxTTL time.Duration, metrics *CacheMetrics) *NegativeCache {
	return &NegativeCache{
		cache:   cache.New(size),
		ttl:     NewTTLManager(minTTL, maxTTL),
		metrics: metrics,
	}
}

// Get retrieves an entry from the negative cache
func (nc *NegativeCache) Get(key uint64) (*CacheEntry, bool) {
	v, ok := nc.cache.Get(key)
	if !ok {
		nc.metrics.Miss()
		return nil, false
	}

	entry := v.(*CacheEntry)
	if entry.IsExpired() {
		nc.cache.Remove(key)
		nc.metrics.Miss()
		return nil, false
	}

	nc.metrics.Hit()
	return entry, true
}

// Set stores an entry in the negative cache
func (nc *NegativeCache) Set(key uint64, entry *CacheEntry) {
	nc.cache.Add(key, entry)
}

// Remove deletes an entry from the negative cache
func (nc *NegativeCache) Remove(key uint64) {
	nc.cache.Remove(key)
}

// Len returns the number of entries in the cache
func (nc *NegativeCache) Len() int {
	return nc.cache.Len()
}
