package authority

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
)

// Delegation represents a cache entry holding the authoritative
// servers for a zone plus the DS RRset that proves the delegation.
type Delegation struct {
	Servers *Servers
	DSSet   []dns.RR
	TTL     time.Duration

	ut time.Time
}

// Cache type.
type Cache struct {
	cache *cache.Cache

	now func() time.Time
}

// NewCache return new cache.
func NewCache() *Cache {
	n := &Cache{
		cache: cache.New(defaultCap),
		now:   time.Now,
	}

	return n
}

// (*Cache).Get returns the delegation entry for a key or an error.
func (n *Cache) Get(key uint64) (*Delegation, error) {
	el, ok := n.cache.Get(key)

	if !ok {
		return nil, cache.ErrCacheNotFound
	}

	d := el.(*Delegation)

	elapsed := n.now().UTC().Sub(d.ut)

	if elapsed >= d.TTL {
		return nil, cache.ErrCacheExpired
	}

	return d, nil
}

// (*Cache).Set stores a delegation entry under the given key.
func (n *Cache) Set(key uint64, dsSet []dns.RR, servers *Servers, ttl time.Duration) {
	if ttl > maximumTTL {
		ttl = maximumTTL
	} else if ttl < minimumTTL {
		ttl = minimumTTL
	}

	n.cache.Add(key, &Delegation{
		Servers: servers,
		DSSet:   dsSet,
		TTL:     ttl,
		ut:      n.now().UTC().Round(time.Second),
	})
}

// (*Cache).Remove remove remove a cache.
func (n *Cache) Remove(key uint64) {
	n.cache.Remove(key)
}

const (
	maximumTTL = 12 * time.Hour
	minimumTTL = 1 * time.Hour
	defaultCap = 1024 * 256
)
