package cache

import (
	"sync"
	"time"
)

// ErrorCache type
type ErrorCache struct {
	mu sync.RWMutex

	ttl uint32
	m   map[uint64]time.Time
	max int
}

// NewErrorCache return new cache
func NewErrorCache(maxcount int, ttl uint32) *ErrorCache {
	c := &ErrorCache{
		m:   make(map[uint64]time.Time, maxcount),
		max: maxcount,
		ttl: ttl,
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *ErrorCache) Get(key uint64) error {
	c.mu.RLock()
	t, ok := c.m[key]
	c.mu.RUnlock()

	if !ok {
		return ErrCacheNotFound
	}

	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(t).Seconds())

	if elapsed >= c.ttl {
		c.Remove(key)
		return ErrCacheExpired
	}

	return nil
}

// Set sets a keys value to a error cache
func (c *ErrorCache) Set(key uint64) error {
	if c.Full() && !c.Exists(key) {
		return ErrCapacityFull
	}

	c.mu.Lock()
	c.m[key] = WallClock.Now().Truncate(time.Second)
	c.mu.Unlock()

	return nil
}

// Remove removes an entry from the cache
func (c *ErrorCache) Remove(key uint64) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *ErrorCache) Exists(key uint64) bool {
	c.mu.RLock()
	_, ok := c.m[key]
	c.mu.RUnlock()
	return ok
}

// Length returns the caches length
func (c *ErrorCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

// Full returns whether or not the cache is full
func (c *ErrorCache) Full() bool {
	if c.max == 0 {
		return false
	}
	return c.Length() >= c.max
}

func (c *ErrorCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, t := range c.m {
		now := WallClock.Now().Truncate(time.Second)
		elapsed := uint32(now.Sub(t).Seconds())

		if elapsed >= c.ttl {
			delete(c.m, key)
			break
		}
	}
}

func (c *ErrorCache) run() {
	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		c.clear()
	}
}
