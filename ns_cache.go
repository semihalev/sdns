package main

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NS represents a cache entry
type NS struct {
	Servers    []*AuthServer
	Network    string
	DSRR       []dns.RR
	TTL        uint32
	UpdateTime time.Time

	mu sync.Mutex
}

// NameServerCache type
type NameServerCache struct {
	mu sync.RWMutex

	m   map[uint64]*NS
	max int
}

// NewNameServerCache return new cache
func NewNameServerCache(maxcount int) *NameServerCache {
	c := &NameServerCache{
		m:   make(map[uint64]*NS, maxcount),
		max: maxcount,
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *NameServerCache) Get(key uint64) (*NS, error) {
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
func (c *NameServerCache) Set(key uint64, dsRR []dns.RR, ttl uint32, servers []*AuthServer) error {
	if c.Full() && !c.Exists(key) {
		return ErrCapacityFull
	}

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
func (c *NameServerCache) Remove(key uint64) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *NameServerCache) Exists(key uint64) bool {
	c.mu.RLock()
	_, ok := c.m[key]
	c.mu.RUnlock()
	return ok
}

// Length returns the caches length
func (c *NameServerCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

// Full returns whether or not the cache is full
func (c *NameServerCache) Full() bool {
	if c.max == 0 {
		return false
	}
	return c.Length() >= c.max
}

func (c *NameServerCache) clear() {
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

func (c *NameServerCache) run() {
	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		c.clear()
	}
}
