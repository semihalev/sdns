package cache

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"golang.org/x/time/rate"
)

// DCache defines the interface for DNS cache implementations.
type DCache interface {
	Get(key uint64) (*CacheEntry, bool)
	Set(key uint64, entry *CacheEntry)
	Remove(key uint64)
	Len() int
}

// CacheEntry represents an immutable cache entry.
type CacheEntry struct {
	msg        *dns.Msg
	stored     time.Time
	ttl        time.Duration
	origTTL    uint32 // Original TTL in seconds for prefetch calculation
	prefetch   atomic.Bool
	rateLimit  int            // Rate limit value (0 = no limit)
	rateLimKey uint64         // Key for shared rate limiter lookup
	ede        *dns.EDNS0_EDE // Preserved EDE information

	// scoped is true when this entry was keyed under an ECS scope
	// rather than the shared key. The prefetch worker can't
	// resynthesise the client IP a scoped query implied, so scoped
	// entries are not eligible for background refresh — they just
	// expire normally. PrefetchEligible() reflects this.
	scoped bool

	// cutUntil bounds the entry's effective lifetime to the
	// delegation cut that produced the answer (GHSA-mqfw-f48p-2vc8,
	// answer-cache ghost): an answer must never be served past the
	// parent-granted lease of the delegation it came from, no matter
	// how long its own TTL is. Zero means unbounded (forwarder and
	// local answers, or no learned delegation on the path). Enforced
	// at read time — remaining() takes the min of the TTL expiry and
	// this deadline — so it also overrides the configured MinTTL
	// floor when the cut is shorter.
	cutUntil time.Time

	// cutKey identifies the delegation cache entry that supplied cutUntil.
	// It is retained for the optional Phase-3 generation design; Phase 1b
	// enforcement depends only on cutUntil.
	cutKey uint64
}

// remaining returns the entry's effective remaining lifetime at now:
// the stored TTL minus elapsed time, further bounded by cutUntil.
func (e *CacheEntry) remaining(now time.Time) time.Duration {
	rem := e.ttl - now.Sub(e.stored)
	if !e.cutUntil.IsZero() {
		if cutRem := e.cutUntil.Sub(now); cutRem < rem {
			rem = cutRem
		}
	}
	return rem
}

// NewCacheEntry creates a new cache entry from a DNS message.
func NewCacheEntry(msg *dns.Msg, ttl time.Duration, rateLimit int) *CacheEntry {
	return NewCacheEntryWithKey(msg, ttl, rateLimit, 0)
}

// NewScopedCacheEntry creates a cache entry that's been keyed under
// an ECS scope. The flag suppresses prefetch (the worker has no
// client IP to derive the scope from on refresh).
func NewScopedCacheEntry(msg *dns.Msg, ttl time.Duration, rateLimit int) *CacheEntry {
	e := NewCacheEntryWithKey(msg, ttl, rateLimit, 0)
	e.scoped = true
	return e
}

// PrefetchEligible reports whether the prefetch worker may refresh
// this entry. Scoped entries are skipped because the worker has no
// client IP, so a refresh would lose the ECS scope and create a
// shared-key entry instead — wrong answer for the wrong audience.
func (e *CacheEntry) PrefetchEligible() bool { return !e.scoped }

// NewCacheEntryWithKey creates a new cache entry with a specific key for rate limiting
func NewCacheEntryWithKey(msg *dns.Msg, ttl time.Duration, rateLimit int, key uint64) *CacheEntry {
	// Create a copy and filter out OPT records (matching V1 behavior)
	msgCopy := new(dns.Msg)
	msgCopy.MsgHdr = msg.MsgHdr
	msgCopy.Compress = msg.Compress
	msgCopy.Question = msg.Question
	msgCopy.Answer = msg.Answer
	msgCopy.Ns = msg.Ns

	var ede *dns.EDNS0_EDE

	// Filter Extra section to remove OPT records but preserve EDE
	if len(msg.Extra) > 0 {
		extra := make([]dns.RR, 0, len(msg.Extra))
		for _, rr := range msg.Extra {
			if opt, ok := rr.(*dns.OPT); ok {
				// Extract EDE from OPT record if present
				for _, option := range opt.Option {
					if e, ok := option.(*dns.EDNS0_EDE); ok {
						ede = e
						break
					}
				}
			} else {
				extra = append(extra, rr)
			}
		}
		msgCopy.Extra = extra
	}

	entry := &CacheEntry{
		msg: msgCopy,
		// Keep the monotonic clock reading. Converting to UTC strips it and
		// would let a backward wall-clock adjustment extend both the TTL and
		// an inherited delegation cut.
		stored:     time.Now(),
		ttl:        ttl,
		origTTL:    uint32(ttl.Seconds()),
		rateLimit:  rateLimit,
		rateLimKey: key,
		ede:        ede,
	}

	return entry
}

// (*CacheEntry).ToMsg toMsg creates a response message with updated TTLs.
func (e *CacheEntry) ToMsg(req *dns.Msg) *dns.Msg {
	now := time.Now()
	remainingTTL := e.remaining(now)

	if remainingTTL <= 0 {
		return nil
	}

	resp := e.msg.Copy()
	originalRcode := resp.Rcode // Save the original Rcode
	originalExtra := resp.Extra // Save the original Extra section
	resp.SetReply(req)
	resp.Rcode = originalRcode // Restore the original Rcode
	resp.Extra = originalExtra // Restore the original Extra section
	resp.Id = req.Id

	// Set Authoritative to false since this is from cache (matching V1 behavior)
	resp.Authoritative = false
	// RecursionAvailable is already preserved from the original message via MsgHdr copy

	// RFC 4035: Never set AD bit when CD bit is set in the request
	if req.CheckingDisabled {
		resp.AuthenticatedData = false
	}

	// Update TTLs
	ttl := uint32(remainingTTL.Seconds())
	for _, rr := range resp.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range resp.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}

	// Restore EDE if it was present in the original response
	// EDE can be present with any response code, not just SERVFAIL
	if e.ede != nil {
		opt := resp.IsEdns0()
		if opt == nil && req.IsEdns0() != nil {
			// Request has EDNS0, so add it to response
			reqOpt := req.IsEdns0()
			opt = &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
					Class:  reqOpt.UDPSize(),
				},
			}
			resp.Extra = append(resp.Extra, opt)
		}

		if opt != nil {
			// Check if EDE already exists
			hasEDE := false
			for _, option := range opt.Option {
				if _, ok := option.(*dns.EDNS0_EDE); ok {
					hasEDE = true
					break
				}
			}
			// Add EDE if not already present
			if !hasEDE {
				opt.Option = append(opt.Option, e.ede)
			}
		}
	}

	return resp
}

// (*CacheEntry).IsExpired isExpired checks if the cache entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return e.remaining(time.Now()) <= 0
}

// (*CacheEntry).TTL TTL returns the remaining TTL in seconds.
func (e *CacheEntry) TTL() int {
	remaining := e.remaining(time.Now())
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Seconds())
}

// (*CacheEntry).ShouldPrefetch shouldPrefetch checks if this entry should be prefetched.
func (e *CacheEntry) ShouldPrefetch(threshold int) bool {
	if threshold <= 0 || e.prefetch.Load() {
		return false
	}

	// Calculate based on original TTL (matching V1 behavior)
	remainingTTL := e.TTL()
	thresholdSeconds := int(float64(threshold) / 100.0 * float64(e.origTTL))
	return remainingTTL <= thresholdSeconds
}

// (*CacheEntry).GetRateLimiter returns the shared rate limiter for this entry
func (e *CacheEntry) GetRateLimiter() *rate.Limiter {
	if e.rateLimit <= 0 {
		return nil
	}
	return getSharedRateLimiter(e.rateLimit, e.rateLimKey)
}

// CacheKey represents a structured cache key.
//
// Scope is the ECS prefix (RFC 7871) the authority claimed its
// answer is scoped to. The zero value means "shared" — an entry
// keyed with no scope is reachable by any client, which is the
// pre-Stage-2 default and how non-ECS traffic and SCOPE=0
// authority answers continue to behave after the upgrade.
type CacheKey struct {
	Question dns.Question
	CD       bool
	Scope    netip.Prefix
}

// (CacheKey).Hash returns the cache key hash. Routes to
// cache.KeyWithPrefix when Scope is valid (family + bit-length +
// address are all folded in so /22 and /24 of the same address
// don't alias), and to the legacy cache.Key — bit-identical to
// pre-Stage-2 — when Scope is the zero value, so old entries keep
// hitting after upgrade. A /0 scope collapses to the unscoped key
// because a /0 answer is semantically "global", same as no scope.
func (k CacheKey) Hash() uint64 {
	if !k.Scope.IsValid() || k.Scope.Bits() == 0 {
		return cache.Key(k.Question, k.CD)
	}
	return cache.KeyWithPrefix(k.Question, k.CD, k.Scope)
}

// CacheConfig holds cache configuration with validation.
type CacheConfig struct {
	Size        int
	Prefetch    int
	PositiveTTL time.Duration
	NegativeTTL time.Duration
	MinTTL      time.Duration
	MaxTTL      time.Duration
	RateLimit   int

	// ECSMaxTTL caps the lifetime of cache entries keyed under an
	// ECS scope. Geo-routed answers tend to go stale faster than
	// the resolver's general MaxTTL would suggest — a CDN
	// re-pointing a /24 between PoPs is normal traffic. Zero
	// disables the cap (scoped entries live as long as their
	// upstream TTL allowed). Populated from cfg.ECS.CacheLimitTTL.
	ECSMaxTTL time.Duration
}

// (CacheConfig).Validate validate checks if the configuration is valid.
func (cc CacheConfig) Validate() error {
	if cc.Size < 1024 {
		return errors.New("cache size must be at least 1024")
	}
	if cc.Prefetch < 0 || cc.Prefetch > 90 {
		return errors.New("prefetch must be between 0 and 90")
	}
	if cc.MinTTL < 0 {
		return errors.New("minimum TTL cannot be negative")
	}
	if cc.MaxTTL < cc.MinTTL {
		return errors.New("maximum TTL must be greater than minimum TTL")
	}
	return nil
}

// TTLManager manages TTL calculations.
type TTLManager struct {
	min, max time.Duration
}

// NewTTLManager creates a new TTL manager.
func NewTTLManager(min, max time.Duration) TTLManager {
	return TTLManager{min: min, max: max}
}

// (TTLManager).Calculate calculate returns the effective TTL within configured bounds.
func (tm TTLManager) Calculate(msgTTL time.Duration) time.Duration {
	if msgTTL < tm.min {
		return tm.min
	}
	if msgTTL > tm.max {
		return tm.max
	}
	return msgTTL
}

// CacheMetrics tracks cache performance metrics.
type CacheMetrics struct {
	hits       atomic.Int64
	misses     atomic.Int64
	evictions  atomic.Int64
	prefetches atomic.Int64
}

// (*CacheMetrics).Hit hit records a cache hit.
func (m *CacheMetrics) Hit() {
	m.hits.Add(1)
	cacheHits.Inc()
}

// (*CacheMetrics).Miss miss records a cache miss.
func (m *CacheMetrics) Miss() {
	m.misses.Add(1)
	cacheMisses.Inc()
}

// (*CacheMetrics).Eviction eviction records a cache eviction.
func (m *CacheMetrics) Eviction() {
	m.evictions.Add(1)
	cacheEvictions.Inc()
}

// (*CacheMetrics).Prefetch prefetch records a prefetch operation.
func (m *CacheMetrics) Prefetch() {
	m.prefetches.Add(1)
	cachePrefetches.Inc()
}

// (*CacheMetrics).Stats stats returns current metrics.
func (m *CacheMetrics) Stats() (hits, misses, evictions, prefetches int64) {
	return m.hits.Load(), m.misses.Load(), m.evictions.Load(), m.prefetches.Load()
}
