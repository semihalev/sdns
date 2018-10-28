package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NS represents a cache entry
type NS struct {
	Servers    *AuthServers
	Network    string
	DSRR       []dns.RR
	TTL        uint32
	UpdateTime time.Time

	mu sync.Mutex
}

// NSCache type
type NSCache struct {
	mu sync.RWMutex

	m map[uint64]*NS
}

// NewNSCache return new cache
func NewNSCache() *NSCache {
	c := &NSCache{
		m: make(map[uint64]*NS),
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *NSCache) Get(key uint64) (*NS, error) {
	c.mu.RLock()
	ns, ok := c.m[key]
	c.mu.RUnlock()

	if !ok {
		return nil, ErrCacheNotFound
	}

	ns.mu.Lock()

	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(ns.UpdateTime).Seconds())
	ns.UpdateTime = now

	if elapsed >= ns.TTL {
		ns.mu.Unlock()
		c.Remove(key)
		return nil, ErrCacheExpired
	}
	ns.TTL -= elapsed
	ns.mu.Unlock()

	return ns, nil
}

// Set sets a keys value to a NS
func (c *NSCache) Set(key uint64, dsRR []dns.RR, ttl uint32, servers *AuthServers) error {
	c.mu.Lock()
	c.m[key] = &NS{
		Servers:    servers,
		Network:    "v4",
		DSRR:       dsRR,
		TTL:        ttl,
		UpdateTime: WallClock.Now().Truncate(time.Second),
	}
	c.mu.Unlock()

	return nil
}

// Remove removes an entry from the cache
func (c *NSCache) Remove(key uint64) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *NSCache) Exists(key uint64) bool {
	c.mu.RLock()
	_, ok := c.m[key]
	c.mu.RUnlock()
	return ok
}

// Length returns the caches length
func (c *NSCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

// Full returns whether or not the cache is full
func (c *NSCache) Full() bool {
	return false
}

func (c *NSCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, ns := range c.m {
		now := WallClock.Now().Truncate(time.Second)
		elapsed := uint32(now.Sub(ns.UpdateTime).Seconds())

		if elapsed >= ns.TTL {
			delete(c.m, key)
			break
		}
	}
}

func (c *NSCache) run() {
	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		c.clear()
	}
}
