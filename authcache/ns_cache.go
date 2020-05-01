package authcache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
)

// NS represents a cache entry
type NS struct {
	Servers *AuthServers
	DSRR    []dns.RR
	TTL     time.Duration

	ut time.Time
}

// NSCache type
type NSCache struct {
	mu sync.RWMutex

	cache *cache.Cache

	now func() time.Time
}

// NewNSCache return new cache
func NewNSCache() *NSCache {
	n := &NSCache{
		cache: cache.New(defaultCap),
		now:   time.Now,
	}

	return n
}

// Get returns the entry for a key or an error
func (n *NSCache) Get(key uint64) (*NS, error) {
	el, ok := n.cache.Get(key)

	if !ok {
		return nil, cache.ErrCacheNotFound
	}

	ns := el.(*NS)

	elapsed := n.now().UTC().Sub(ns.ut)

	if elapsed >= ns.TTL {
		return nil, cache.ErrCacheExpired
	}

	return ns, nil
}

// Set sets a keys value to a NS
func (n *NSCache) Set(key uint64, dsRR []dns.RR, servers *AuthServers, ttl time.Duration) {
	if ttl > maximumTTL {
		ttl = maximumTTL
	}

	n.cache.Add(key, &NS{
		Servers: servers,
		DSRR:    dsRR,
		TTL:     ttl,
		ut:      n.now().UTC().Round(time.Second),
	})
}

const (
	maximumTTL = 12 * time.Hour
	defaultCap = 1024 * 256
)
