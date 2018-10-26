package main

import (
	"strings"
	"sync"
	"time"

	"github.com/semihalev/log"
)

// ErrorCache type
type ErrorCache struct {
	mu sync.RWMutex

	ttl uint32
	m   map[string]time.Time
	max int
}

// NewErrorCache return new cache
func NewErrorCache(maxcount int, ttl uint32) *ErrorCache {
	c := &ErrorCache{
		m:   make(map[string]time.Time, maxcount),
		max: maxcount,
		ttl: ttl,
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *ErrorCache) Get(key string) error {
	key = strings.ToLower(key)

	c.mu.RLock()
	t, ok := c.m[key]
	c.mu.RUnlock()

	if !ok {
		log.Debug("Error cache miss", "key", key)
		return ErrCacheNotFound
	}

	//Truncate time to the second, so that subsecond queries won't keep moving
	//forward the last update time without touching the TTL
	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(t).Seconds())

	if elapsed > c.ttl {
		log.Debug("Error cache expired", "key", key)
		c.Remove(key)
		return ErrCacheExpired
	}

	return nil
}

// Set sets a keys value to a error cache
func (c *ErrorCache) Set(key string) error {
	key = strings.ToLower(key)

	if c.Full() && !c.Exists(key) {
		return ErrCapacityFull
	}

	c.mu.Lock()
	c.m[key] = WallClock.Now().Truncate(time.Second)
	c.mu.Unlock()

	return nil
}

// Remove removes an entry from the cache
func (c *ErrorCache) Remove(key string) {
	key = strings.ToLower(key)

	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *ErrorCache) Exists(key string) bool {
	key = strings.ToLower(key)

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

		if elapsed > c.ttl {
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
