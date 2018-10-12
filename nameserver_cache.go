package main

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NS represents a cache entry
type NS struct {
	Servers        []string
	DSRR           []dns.RR
	TTL            uint32
	LastUpdateTime time.Time
}

// NameServerCache type
type NameServerCache struct {
	mu sync.RWMutex

	Backend  map[string]*NS
	Maxcount int
}

// NewNameServerCache return new cache
func NewNameServerCache(maxcount int) *NameServerCache {
	c := &NameServerCache{
		Backend:  make(map[string]*NS, maxcount),
		Maxcount: maxcount,
	}

	go c.run()

	return c
}

// Get returns the entry for a key or an error
func (c *NameServerCache) Get(key string) (*NS, error) {
	key = strings.ToLower(key)

	c.mu.RLock()
	ns, ok := c.Backend[key]
	c.mu.RUnlock()

	if !ok {
		return nil, KeyNotFound{key}
	}

	//Truncate time to the second, so that subsecond queries won't keep moving
	//forward the last update time without touching the TTL
	now := WallClock.Now().Truncate(time.Second)
	elapsed := uint32(now.Sub(ns.LastUpdateTime).Seconds())
	ns.LastUpdateTime = now

	if elapsed > ns.TTL {
		c.Remove(key)
		return nil, KeyExpired{key}
	}
	ns.TTL -= elapsed

	return ns, nil
}

// Set sets a keys value to a NS
func (c *NameServerCache) Set(key string, dsRR []dns.RR, ttl uint32, servers []string) error {
	key = strings.ToLower(key)

	if c.Full() && !c.Exists(key) {
		return CacheIsFull{}
	}

	ns := NS{servers, dsRR, ttl, WallClock.Now().Truncate(time.Second)}
	c.mu.Lock()
	c.Backend[key] = &ns
	c.mu.Unlock()

	return nil
}

// Remove removes an entry from the cache
func (c *NameServerCache) Remove(key string) {
	key = strings.ToLower(key)

	c.mu.Lock()
	delete(c.Backend, key)
	c.mu.Unlock()
}

// Exists returns whether or not a key exists in the cache
func (c *NameServerCache) Exists(key string) bool {
	key = strings.ToLower(key)

	c.mu.RLock()
	_, ok := c.Backend[key]
	c.mu.RUnlock()
	return ok
}

// Length returns the caches length
func (c *NameServerCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Backend)
}

// Full returns whether or not the cache is full
func (c *NameServerCache) Full() bool {
	if c.Maxcount == 0 {
		return false
	}
	return c.Length() >= c.Maxcount
}

func (c *NameServerCache) run() {
	ticker := time.NewTicker(time.Hour)

	for range ticker.C {
		c.mu.Lock()
		for key, ns := range c.Backend {
			now := WallClock.Now().Truncate(time.Second)
			elapsed := uint32(now.Sub(ns.LastUpdateTime).Seconds())

			if elapsed > ns.TTL {
				delete(c.Backend, key)
				break
			}
		}
		c.mu.Unlock()
	}
}
