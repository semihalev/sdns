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

	elapsed := n.now().UTC().Sub(el.(*NS).ut)

	if elapsed >= maximumTTL {
		return nil, cache.ErrCacheExpired
	}

	return el.(*NS), nil
}

// Set sets a keys value to a NS
func (n *NSCache) Set(key uint64, dsRR []dns.RR, servers *AuthServers) {
	n.cache.Add(key, &NS{
		Servers: servers,
		DSRR:    dsRR,
		ut:      n.now().UTC().Round(time.Second),
	})
}

const (
	maximumTTL = time.Hour
	defaultCap = 1024 * 256
)
