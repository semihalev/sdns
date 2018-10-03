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

	TTL      uint32
	Backend  map[string]time.Time
	Maxcount int
}

// NewErrorCache return new cache
func NewErrorCache(maxcount int, ttl uint32) *ErrorCache {
	c := &ErrorCache{
		Backend:  make(map[string]time.Time, maxcount),
		Maxcount: maxcount,
		TTL:      ttl,
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *ErrorCache) Get(key string) error {
	key = strings.ToLower(key)

	c.mu.RLock()
	t, ok := c.Backend[key]
	c.mu.RUnlock()

	if !ok {
		log.Debug("Error cache miss", "key", key)
		return KeyNotFound{key}
	}

	//Truncate time to the second, so that subsecond queries won't keep moving
	//forward the last update time without touching the TTL
	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(t).Seconds())

	if elapsed > c.TTL {
		log.Debug("Error cache expired", "key", key)
		c.Remove(key)
		return KeyExpired{key}
	}

	return nil
}

// Set sets a keys value to a error cache
func (c *ErrorCache) Set(key string) error {
	key = strings.ToLower(key)

	if c.Full() && !c.Exists(key) {
		return CacheIsFull{}
	}

	c.mu.Lock()
	c.Backend[key] = WallClock.Now().Truncate(time.Second)
	c.mu.Unlock()

	return nil
}

// Remove removes an entry from the cache
func (c *ErrorCache) Remove(key string) {
	key = strings.ToLower(key)

	c.mu.Lock()
	delete(c.Backend, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *ErrorCache) Exists(key string) bool {
	key = strings.ToLower(key)

	c.mu.RLock()
	_, ok := c.Backend[key]
	c.mu.RUnlock()
	return ok
}

// Length returns the caches length
func (c *ErrorCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Backend)
}

// Full returns whether or not the cache is full
func (c *ErrorCache) Full() bool {
	if c.Maxcount == 0 {
		return false
	}
	return c.Length() >= c.Maxcount
}

func (c *ErrorCache) run() {
	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		c.mu.Lock()
		for key, t := range c.Backend {
			now := WallClock.Now().Truncate(time.Second)
			elapsed := uint32(now.Sub(t).Seconds())

			if elapsed > c.TTL {
				delete(c.Backend, key)
				break
			}
		}
		c.mu.Unlock()
	}
}
