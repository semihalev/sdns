package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// LimiterStore is a specialized store for rate limiters
// It uses a simple circular buffer approach to avoid expensive evictions
type LimiterStore struct {
	mu       sync.RWMutex
	limiters map[uint64]*timestampedLimiter
	maxSize  int
	rate     int
}

type timestampedLimiter struct {
	limiter *limiter
	// lastSeen is read from Cleanup / evictOne under the store's
	// exclusive lock and written by Get on every hit. Using an
	// atomic avoids upgrading the hot-path Get to an exclusive
	// lock just to stamp a timestamp, while still letting
	// concurrent writers/readers see a consistent value.
	lastSeen atomic.Int64 // unix nanoseconds
}

func (tl *timestampedLimiter) touch() { tl.lastSeen.Store(time.Now().UnixNano()) }
func (tl *timestampedLimiter) seen() time.Time {
	return time.Unix(0, tl.lastSeen.Load())
}

// NewLimiterStore creates a new limiter store
func NewLimiterStore(maxSize, rateLimit int) *LimiterStore {
	return &LimiterStore{
		limiters: make(map[uint64]*timestampedLimiter),
		maxSize:  maxSize,
		rate:     rateLimit,
	}
}

// Get retrieves or creates a limiter for the given key
func (s *LimiterStore) Get(key uint64) *limiter {
	s.mu.RLock()
	if tl, ok := s.limiters[key]; ok {
		tl.touch() // atomic store — safe under RLock
		s.mu.RUnlock()
		return tl.limiter
	}
	s.mu.RUnlock()

	// Create new limiter
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if tl, ok := s.limiters[key]; ok {
		tl.touch()
		return tl.limiter
	}

	// Check if we need to evict
	if len(s.limiters) >= s.maxSize {
		s.evictOne()
	}

	// Create new limiter
	limit := rate.Limit(0)
	if s.rate > 0 {
		limit = rate.Every(time.Minute / time.Duration(s.rate))
	}

	rl := rate.NewLimiter(limit, s.rate)
	l := &limiter{rl: rl}
	l.cookie.Store("")

	tl := &timestampedLimiter{limiter: l}
	tl.touch()
	s.limiters[key] = tl

	return l
}

// evictOne removes the oldest entry
func (s *LimiterStore) evictOne() {
	var oldestKey uint64
	var oldestTime time.Time
	first := true

	// Find the oldest entry
	for k, v := range s.limiters {
		seen := v.seen()
		if first || seen.Before(oldestTime) {
			oldestKey = k
			oldestTime = seen
			first = false
		}

		// Early exit after checking a sample
		if !first && len(s.limiters) > 1000 {
			// For large maps, just sample the first 100 entries
			// This avoids iterating the entire map
			break
		}
	}

	if !first {
		delete(s.limiters, oldestKey)
	}
}

// Cleanup removes entries older than duration
func (s *LimiterStore) Cleanup(olderThan time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	for k, v := range s.limiters {
		if v.seen().Before(cutoff) {
			delete(s.limiters, k)
		}
	}
}

// Len returns the number of limiters
func (s *LimiterStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.limiters)
}
