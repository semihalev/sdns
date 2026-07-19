package authority

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
)

// Delegation represents a cache entry holding the authoritative
// servers for a zone plus the DS RRset that proves the delegation.
//
// ExpiresAt is a single immutable absolute expiry (monotonic clock
// retained). Storing the absolute deadline — rather than a duration
// re-anchored at insertion — is what lets a descendant delegation inherit
// an ancestor's shorter lease without a scheduler pause between "compute
// remaining" and "store" silently re-inflating it (GHSA-mqfw-f48p-2vc8,
// Phoenix downward-delegation variant).
type Delegation struct {
	Servers   *Servers
	DSSet     []dns.RR
	ExpiresAt time.Time
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

	// now() and ExpiresAt both retain the monotonic clock reading, so a
	// wall-clock step cannot extend or prematurely expire the lease.
	if !n.now().Before(d.ExpiresAt) {
		return nil, cache.ErrCacheExpired
	}

	return d, nil
}

// (*Cache).Set stores a delegation entry that expires ttl from now.
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

	n.store(key, dsSet, servers, n.now().Add(ttl))
}

// (*Cache).SetUntil stores a delegation with an ABSOLUTE expiry, capped at
// the 12h ceiling. Resolver writes use this so a parent-granted deadline —
// possibly inherited from a shorter-lived ancestor — is stored verbatim
// rather than reconstructed from time.Until(deadline): any delay (including a
// scheduler pause) between computing the remaining duration and Set's
// now.Add(ttl) would otherwise restart the lease.
func (n *Cache) SetUntil(key uint64, dsSet []dns.RR, servers *Servers, expiresAt time.Time) {
	now := n.now()
	if !expiresAt.After(now) {
		return
	}
	if ceiling := now.Add(maximumTTL); expiresAt.After(ceiling) {
		expiresAt = ceiling
	}

	n.store(key, dsSet, servers, expiresAt)
}

func (n *Cache) store(key uint64, dsSet []dns.RR, servers *Servers, expiresAt time.Time) {
	n.cache.Add(key, &Delegation{
		Servers:   servers,
		DSSet:     dsSet,
		ExpiresAt: expiresAt,
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
