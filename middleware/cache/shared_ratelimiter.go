package cache

import (
	"hash/fnv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// sharedRateLimiterPool manages a pool of shared rate limiters to reduce memory usage
type sharedRateLimiterPool struct {
	limiters []*rate.Limiter
	size     int
}

var (
	rateLimiterPools = make(map[int]*sharedRateLimiterPool)
	poolsMu          sync.RWMutex
)

// getSharedRateLimiter returns a shared rate limiter for the given rate limit and key
func getSharedRateLimiter(rateLimit int, key uint64) *rate.Limiter {
	if rateLimit <= 0 {
		return nil
	}

	poolsMu.RLock()
	pool, exists := rateLimiterPools[rateLimit]
	poolsMu.RUnlock()

	if !exists {
		poolsMu.Lock()
		// Double-check after acquiring write lock
		pool, exists = rateLimiterPools[rateLimit]
		if !exists {
			// Create a new pool for this rate limit
			// Use 997 (prime number) for better distribution
			poolSize := 997
			pool = &sharedRateLimiterPool{
				limiters: make([]*rate.Limiter, poolSize),
				size:     poolSize,
			}

			// Initialize all limiters in the pool
			limit := rate.Every(time.Second / time.Duration(rateLimit))
			for i := 0; i < poolSize; i++ {
				pool.limiters[i] = rate.NewLimiter(limit, rateLimit)
			}

			rateLimiterPools[rateLimit] = pool
		}
		poolsMu.Unlock()
	}

	// Use FNV-1a hash for better distribution
	h := fnv.New64a()
	h.Write([]byte{byte(key), byte(key >> 8), byte(key >> 16), byte(key >> 24),
		byte(key >> 32), byte(key >> 40), byte(key >> 48), byte(key >> 56)})
	index := h.Sum64() % uint64(pool.size)

	return pool.limiters[index]
}
