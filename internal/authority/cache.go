package authority

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
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

	// Monotonic elapsed: n.now() and d.ut both retain the monotonic clock
	// reading (no .UTC()/.Round(), which would strip it), so a wall-clock
	// step cannot extend or prematurely expire a delegation lease.
	elapsed := n.now().Sub(d.ut)

	if elapsed >= d.TTL {
		return nil, cache.ErrCacheExpired
	}

	return d, nil
}

// (*Cache).Set stores a delegation entry under the given key.
//
// The lease must honour the parent-granted TTL. The former one-hour lower
// clamp inflated a short referral TTL (e.g. a 4s delegation) into a one-hour
// lease, which let a withdrawn child zone be kept alive indefinitely from its
// own authoritative NS answer — the ghost-domain vulnerability
// (GHSA-mqfw-f48p-2vc8). Only the upper bound is clamped now; a non-positive
// TTL is not cached at all (caching an already-expired entry is pointless and
// a zero TTL means "do not cache").
func (n *Cache) Set(key uint64, dsSet []dns.RR, servers *Servers, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	if ttl > maximumTTL {
		ttl = maximumTTL
	}

	n.cache.Add(key, &Delegation{
		Servers: servers,
		DSSet:   dsSet,
		TTL:     ttl,
		ut:      n.now(),
	})
}

// (*Cache).Remove remove remove a cache.
func (n *Cache) Remove(key uint64) {
	n.cache.Remove(key)
}

const (
	maximumTTL = 12 * time.Hour
	defaultCap = 1024 * 256
)
