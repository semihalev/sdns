// Package kubernetes - Simple DNS cache
package kubernetes

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache stores DNS responses.
type Cache struct {
	entries map[string]*cacheEntry
	mu      sync.RWMutex
}

type cacheEntry struct {
	msg    *dns.Msg
	expiry time.Time
}

// NewCache creates a new cache.
func NewCache() *Cache {
	c := &Cache{
		entries: make(map[string]*cacheEntry),
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// Get retrieves a cached response.
func (c *Cache) Get(qname string, qtype uint16) *dns.Msg {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey(qname, qtype)
	entry := c.entries[key]

	if entry == nil || time.Now().After(entry.expiry) {
		return nil
	}

	return entry.msg
}

// Set stores a response in cache.
func (c *Cache) Set(qname string, qtype uint16, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(qname, qtype)

	// Determine TTL from response
	ttl := uint32(30) // Default 30 seconds
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}

	c.entries[key] = &cacheEntry{
		msg:    msg.Copy(),
		expiry: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// cleanup removes expired entries.
func (c *Cache) cleanup() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiry) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// cacheKey generates cache key.
func cacheKey(qname string, qtype uint16) string {
	return qname + "|" + dns.TypeToString[qtype]
}
