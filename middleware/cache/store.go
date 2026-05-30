package cache

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// Store is the cache backing for the cache middleware. It owns nothing
// directly — the positive/negative sub-caches are constructed by
// Cache.New and shared with Store — but it centralises classification,
// keying, and TTL handling so callers outside ServeDNS (resolver
// sub-queries, queryer-driven prefetch, future API purge wiring)
// don't need to understand the wire-write rules in
// ResponseWriter.WriteMsg.
//
// SetFromResponse keys on the caller-supplied keyCD rather than on
// resp.CheckingDisabled to make the keying contract explicit at every
// call site — Forwarder and Resolver both temporarily mutate CD on
// the upstream request, and silent reliance on resp.CheckingDisabled
// is the kind of thing that splits CD=1 and CD=0 lookups across
// stale entries when a future change forgets to restore.
type Store struct {
	positive *PositiveCache
	negative *NegativeCache
	cfg      CacheConfig
}

// NewStore returns a Store backed by the supplied sub-caches. The
// caches are shared with the surrounding *Cache; this constructor
// does not allocate them.
func NewStore(positive *PositiveCache, negative *NegativeCache, cfg CacheConfig) *Store {
	return &Store{positive: positive, negative: negative, cfg: cfg}
}

// Lookup returns the cache entry for req without materialising a
// response. Used by callers that need to inspect TTL or prefetch
// flags before deciding whether to consume the entry.
func (s *Store) Lookup(req *dns.Msg) (*CacheEntry, bool) {
	if len(req.Question) == 0 {
		return nil, false
	}
	return s.LookupByKey(CacheKey{Question: req.Question[0], CD: req.CheckingDisabled}.Hash())
}

// LookupByKey is the pre-keyed form of Lookup, used by hot paths
// inside the cache middleware that already computed the key.
func (s *Store) LookupByKey(key uint64) (*CacheEntry, bool) {
	if entry, ok := s.positive.Get(key); ok {
		return entry, true
	}
	if entry, ok := s.negative.Get(key); ok {
		return entry, true
	}
	return nil, false
}

// Get returns a materialised cached response for req. Reply
// header/ID/CD/AD interaction is handled by CacheEntry.ToMsg, which
// needs req for SetReply.
func (s *Store) Get(req *dns.Msg) (*dns.Msg, bool) {
	entry, ok := s.Lookup(req)
	if !ok {
		return nil, false
	}
	msg := entry.ToMsg(req)
	if msg == nil {
		// Entry expired between Lookup and ToMsg.
		return nil, false
	}
	return msg, true
}

// SetFromResponse classifies resp (positive / NXDOMAIN+NODATA /
// SERVFAIL) and stores it under (resp.Question[0], keyCD). CHAOS
// signalling responses are skipped, matching ResponseWriter.WriteMsg.
func (s *Store) SetFromResponse(resp *dns.Msg, keyCD bool) {
	if len(resp.Question) == 0 {
		return
	}
	q := resp.Question[0]
	if (debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO) ||
		(q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL) {
		return
	}
	s.SetFromResponseWithKey(CacheKey{Question: q, CD: keyCD}.Hash(), resp)
}

// SetFromResponseWithKey is the pre-keyed form of SetFromResponse,
// used by ResponseWriter.WriteMsg, which has the key already.
func (s *Store) SetFromResponseWithKey(key uint64, resp *dns.Msg) {
	s.setFromResponseWithKey(key, resp, false)
}

// SetFromResponseScoped is SetFromResponseWithKey for entries that
// were keyed under an ECS scope (RFC 7871 §7.1.2). The entry's
// PrefetchEligible is false — the prefetch worker has no client IP
// to derive ECS from, so refreshing a scoped entry would lose its
// scope and store the wrong-audience answer.
func (s *Store) SetFromResponseScoped(key uint64, resp *dns.Msg) {
	s.setFromResponseWithKey(key, resp, true)
}

func (s *Store) setFromResponseWithKey(key uint64, resp *dns.Msg, scoped bool) {
	mt, _ := dnsutil.ClassifyResponse(resp, time.Now().UTC())
	filtered := filterCacheableAnswer(resp)
	msgTTL := dnsutil.CalculateCacheTTL(filtered, mt)

	// Scoped (ECS) entries get an additional cap: geo answers go
	// stale faster than the resolver's normal MaxTTL would allow,
	// and a misconfigured upstream sending a huge TTL on a /24
	// answer shouldn't pin that audience-specific entry for hours.
	// Zero ECSMaxTTL leaves scoped writes uncapped (operator opted
	// in to long-lived scoped entries).
	capTTL := func(ttl time.Duration) time.Duration {
		if scoped && s.cfg.ECSMaxTTL > 0 && ttl > s.cfg.ECSMaxTTL {
			return s.cfg.ECSMaxTTL
		}
		return ttl
	}

	newEntry := func(msg *dns.Msg, ttl time.Duration) *CacheEntry {
		if scoped {
			e := NewScopedCacheEntry(msg, ttl, s.cfg.RateLimit)
			e.rateLimKey = key
			return e
		}
		return NewCacheEntryWithKey(msg, ttl, s.cfg.RateLimit, key)
	}

	switch mt {
	case dnsutil.TypeSuccess, dnsutil.TypeReferral, dnsutil.TypeNXDomain, dnsutil.TypeNoRecords:
		ttl := capTTL(s.positive.ttl.Calculate(msgTTL))
		s.positive.Set(key, newEntry(filtered, ttl))
	case dnsutil.TypeServerFailure:
		ttl := capTTL(s.negative.ttl.Calculate(msgTTL))
		s.negative.Set(key, newEntry(filtered, ttl))
	}
}

// SetEntryWithKey replaces a stored entry directly. Used by
// Cache.Set's compatibility path where a caller already constructed
// the CacheEntry (e.g. prefetch worker writing back a response with
// adjusted origTTL).
func (s *Store) SetEntryWithKey(key uint64, entry *CacheEntry, mt dnsutil.ResponseType) {
	switch mt {
	case dnsutil.TypeSuccess, dnsutil.TypeReferral, dnsutil.TypeNXDomain, dnsutil.TypeNoRecords:
		s.positive.Set(key, entry)
	case dnsutil.TypeServerFailure:
		s.negative.Set(key, entry)
	}
}

// Purge removes both CD=true and CD=false entries for q from
// positive and negative caches, including ECS-scoped entries.
//
// Scoped entries don't have a deterministic key the caller could
// reproduce without enumerating every (qname, scope) the cache
// has ever seen — there's no per-qname index. We sweep them with
// ForEach: collect matching keys in one pass (snapshotting the
// per-segment locks individually), then Remove outside the
// iteration to avoid mutate-during-iterate hazards.
//
// O(n) on the cache size; Purge is rare (explicit operator API
// call) so the linear scan is acceptable. If purge becomes
// hot, a per-qname index would lift this back to O(matches).
func (s *Store) Purge(q dns.Question) {
	for _, cd := range []bool{false, true} {
		key := CacheKey{Question: q, CD: cd}.Hash()
		s.positive.Remove(key)
		s.negative.Remove(key)
	}

	type located struct {
		positive bool
		key      uint64
	}
	var hits []located
	s.ForEach(func(positive bool, key uint64, e *CacheEntry) bool {
		if e == nil || !e.scoped || e.msg == nil || len(e.msg.Question) == 0 {
			return true
		}
		eq := e.msg.Question[0]
		if eq.Name == q.Name && eq.Qtype == q.Qtype && eq.Qclass == q.Qclass {
			hits = append(hits, located{positive: positive, key: key})
		}
		return true
	})
	for _, h := range hits {
		if h.positive {
			s.positive.Remove(h.key)
		} else {
			s.negative.Remove(h.key)
		}
	}
}

// PositiveLen returns the number of entries in the positive cache.
func (s *Store) PositiveLen() int { return s.positive.Len() }

// NegativeLen returns the number of entries in the negative cache.
func (s *Store) NegativeLen() int { return s.negative.Len() }

// ForEach iterates over positive then negative entries. Returning
// false from fn stops iteration. Iteration is not atomic with
// concurrent updates.
func (s *Store) ForEach(fn func(positive bool, key uint64, entry *CacheEntry) bool) {
	keepGoing := true
	for i, sub := range []*cache.Cache{s.positive.cache, s.negative.cache} {
		sub.ForEach(func(key uint64, value any) bool {
			if keepGoing {
				if entry, ok := value.(*CacheEntry); ok && entry != nil {
					keepGoing = fn(i == 0, key, entry)
				}
			}
			return keepGoing
		})
	}
}
