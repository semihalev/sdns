package cache

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/util"
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
	mt, _ := util.ClassifyResponse(resp, time.Now().UTC())
	filtered := filterCacheableAnswer(resp)
	msgTTL := util.CalculateCacheTTL(filtered, mt)

	switch mt {
	case util.TypeSuccess, util.TypeReferral, util.TypeNXDomain, util.TypeNoRecords:
		ttl := s.positive.ttl.Calculate(msgTTL)
		s.positive.Set(key, NewCacheEntryWithKey(filtered, ttl, s.cfg.RateLimit, key))
	case util.TypeServerFailure:
		ttl := s.negative.ttl.Calculate(msgTTL)
		s.negative.Set(key, NewCacheEntryWithKey(filtered, ttl, s.cfg.RateLimit, key))
	}
}

// SetEntryWithKey replaces a stored entry directly. Used by
// Cache.Set's compatibility path where a caller already constructed
// the CacheEntry (e.g. prefetch worker writing back a response with
// adjusted origTTL).
func (s *Store) SetEntryWithKey(key uint64, entry *CacheEntry, mt util.ResponseType) {
	switch mt {
	case util.TypeSuccess, util.TypeReferral, util.TypeNXDomain, util.TypeNoRecords:
		s.positive.Set(key, entry)
	case util.TypeServerFailure:
		s.negative.Set(key, entry)
	}
}

// Purge removes both CD=true and CD=false entries for q from
// positive and negative caches.
func (s *Store) Purge(q dns.Question) {
	for _, cd := range []bool{false, true} {
		key := CacheKey{Question: q, CD: cd}.Hash()
		s.positive.Remove(key)
		s.negative.Remove(key)
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
