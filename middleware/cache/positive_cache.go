package cache

import (
	"time"

	"github.com/semihalev/sdns/internal/cache"
)

// answerExpiryHorizon is the span of the answer cache's expiry ring: a
// bucket is 1/256 of it, about 14 s, and an answer that can be served for
// longer waits in the far list until it comes within reach.
const answerExpiryHorizon = time.Hour

// PositiveCache handles successful DNS responses.
type PositiveCache struct {
	cache   *cache.Cache[*CacheEntry]
	ttl     TTLManager
	metrics *CacheMetrics

	// life is how long from now an entry can still be served, the instant
	// its expiry record is filed for. The Store sets it from its
	// serve-stale bounds; without one, an entry lives for its TTL and
	// lease.
	life func(e *CacheEntry, now time.Time) time.Duration
}

// NewPositiveCache creates a new positive cache.
func NewPositiveCache(size int, minTTL, maxTTL time.Duration, metrics *CacheMetrics) *PositiveCache {
	return &PositiveCache{
		cache:   cache.NewWithExpiry[*CacheEntry](size, answerExpiryHorizon),
		ttl:     NewTTLManager(minTTL, maxTTL),
		metrics: metrics,
	}
}

// lifeOf is how long from now e can still be served.
func (pc *PositiveCache) lifeOf(e *CacheEntry, now time.Time) time.Duration {
	if pc.life != nil {
		return pc.life(e, now)
	}
	ttl, lease := e.remainingBounds(now)
	if !e.cutUntil.IsZero() && lease < ttl {
		return lease
	}
	return ttl
}

// (*PositiveCache).Get get retrieves an entry from the positive cache.
// Hit/Miss metrics are NOT recorded here, checkCache consults both
// positive and negative caches per request and records the aggregate
// result once, so pushing metrics in here would double-count both
// sides of a single miss.
func (pc *PositiveCache) Get(key uint64) (*CacheEntry, bool) {
	entry, ok := pc.cache.Get(key)
	if !ok {
		return nil, false
	}

	if entry.IsExpired() {
		pc.cache.CompareAndDelete(key, entry)
		return nil, false
	}

	return entry, true
}

// retained returns an entry without applying expiry cleanup. Serve-stale is
// the only production caller: it needs the immutable wire image after the
// ordinary TTL has elapsed, while every public/fresh lookup keeps Get's
// historical miss-and-delete behavior when the feature is disabled.
func (pc *PositiveCache) retained(key uint64) (*CacheEntry, bool) {
	return pc.cache.Get(key)
}

// (*PositiveCache).Set set stores an entry in the positive cache.
func (pc *PositiveCache) Set(key uint64, entry *CacheEntry) {
	pc.cache.AddFor(key, entry, pc.lifeOf(entry, time.Now()))
}

// (*PositiveCache).Remove remove deletes an entry from the positive cache.
func (pc *PositiveCache) Remove(key uint64) {
	pc.cache.Remove(key)
}

// (*PositiveCache).Len len returns the number of entries in the cache.
func (pc *PositiveCache) Len() int {
	return pc.cache.Len()
}
