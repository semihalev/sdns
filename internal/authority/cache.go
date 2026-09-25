package authority

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/lease"
)

// Delegation represents a cache entry holding the authoritative
// servers for a zone plus the DS RRset that proves the delegation.
//
// Lease is the immutable absolute expiry, always bounded. Storing the
// absolute deadlines, rather than a duration re-anchored at insertion, is
// what lets a descendant delegation inherit an ancestor's shorter lease
// without a scheduler pause between "compute remaining" and "store"
// silently re-inflating it (GHSA-mqfw-f48p-2vc8, Phoenix
// downward-delegation variant). A delegation served from a verified root
// copy also inherits the copy's signature expiration, a wall-clock
// instant, and the lease keeps it on that clock.
type Delegation struct {
	Servers *Servers
	DSSet   []dns.RR
	Lease   lease.Lease
}

// Cache type.
type Cache struct {
	cache *cache.Cache[*Delegation]

	now func() time.Time
}

// NewCache return new cache.
func NewCache() *Cache {
	n := &Cache{
		cache: cache.New[*Delegation](defaultCap),
		now:   time.Now,
	}

	return n
}

// (*Cache).Get returns the delegation entry for a key or an error.
func (n *Cache) Get(key uint64) (*Delegation, error) {
	d, ok := n.cache.Get(key)

	if !ok {
		return nil, cache.ErrCacheNotFound
	}

	// now() retains the monotonic clock reading, so a wall-clock step
	// cannot extend or prematurely expire a monotonic deadline, and a
	// wall-clock one ends when the wall clock reaches it.
	if d.Lease.Expired(n.now()) {
		return nil, cache.ErrCacheExpired
	}

	return d, nil
}

// (*Cache).Set stores a delegation entry that expires ttl from now.
//
// The lease must honour the parent-granted TTL. The former one-hour lower
// clamp inflated a short referral TTL (e.g. a 4s delegation) into a one-hour
// lease, which let a withdrawn child zone be kept alive indefinitely from its
// own authoritative NS answer, the ghost-domain vulnerability
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

	n.store(key, dsSet, servers, lease.Until(n.now().Add(ttl)))
}

// (*Cache).SetUntil stores a delegation with an ABSOLUTE expiry, capped at
// the 12h ceiling. Resolver writes use this so a parent-granted deadline,
// possibly inherited from a shorter-lived ancestor, is stored verbatim
// rather than reconstructed from time.Until(deadline): any delay (including a
// scheduler pause) between computing the remaining duration and Set's
// now.Add(ttl) would otherwise restart the lease.
func (n *Cache) SetUntil(key uint64, dsSet []dns.RR, servers *Servers, expiresAt lease.Lease) {
	expiresAt, ok := n.admit(expiresAt)
	if !ok {
		return
	}

	n.store(key, dsSet, servers, expiresAt)
}

// admit caps a lease at the 12h ceiling and refuses one that is unbounded
// or already past: a delegation always has a lease, and caching an expired
// one is pointless.
func (n *Cache) admit(expiresAt lease.Lease) (lease.Lease, bool) {
	now := n.now()
	if expiresAt.IsZero() || expiresAt.Expired(now) {
		return lease.Lease{}, false
	}
	return expiresAt.Min(lease.Until(now.Add(maximumTTL))), true
}

// (*Cache).SetUntilIfAbsent is SetUntil for provisional writers: it stores
// only when the key holds no live delegation, absent, or present but past
// its expiry. A live entry always wins, atomically: the absent case inserts
// under the segment write lock (AddIfAbsent), and the expired case replaces
// exactly the expired value it examined (CompareAndSwap), so a real lease
// published by a concurrent walk can never be displaced by the provisional
// one racing it.
//
// It returns the delegation that is live under the key afterwards, the one
// it stored, or the one that beat it. Callers that go on to use the
// delegation must use the returned value and not their own inputs: servers,
// DS set and expiry belong to one entry, and pairing a winner's servers
// with a loser's DS chain would validate one delegation's answers against
// another's keys. A nil return means nothing is live (a past deadline is
// not stored).
func (n *Cache) SetUntilIfAbsent(key uint64, dsSet []dns.RR, servers *Servers, expiresAt lease.Lease) *Delegation {
	expiresAt, ok := n.admit(expiresAt)
	if !ok {
		return nil
	}

	d := &Delegation{
		Servers: servers,
		DSSet:   dsSet,
		Lease:   expiresAt,
	}
	for {
		cur, ok := n.cache.Get(key)
		if !ok {
			if n.cache.AddIfAbsent(key, d) {
				return d
			}
			// Lost the insert race; re-examine what landed.
			continue
		}
		if !cur.Lease.Expired(n.now()) {
			return cur
		}
		if n.cache.CompareAndSwap(key, cur, d) {
			return d
		}
		// The expired value was replaced under us; re-examine the newer one.
	}
}

func (n *Cache) store(key uint64, dsSet []dns.RR, servers *Servers, expiresAt lease.Lease) {
	n.cache.Add(key, &Delegation{
		Servers: servers,
		DSSet:   dsSet,
		Lease:   expiresAt,
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
