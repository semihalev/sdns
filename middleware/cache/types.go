package cache

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/dnsutil"
	// Aliased: this file's local "wire" is the packed body itself.
	wirepack "github.com/semihalev/sdns/internal/wire"
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
//
// The response is retained in packed wire form: one pointer-free byte slice
// instead of a parsed message graph of ~two dozen heap objects. At the field
// scale that graph was the dominant GC mark cost (18M live objects on a warm
// 743k-entry canary). Serving unpacks a fresh message per hit — comparable
// work to the deep Copy the parsed representation already paid, since a
// served message must be privately mutable either way.
type CacheEntry struct {
	wire []byte
	// stripped is wire without its DNSSEC records, packed at admission for
	// clients that did not set DO. It is nil unless wire carries DNSSEC
	// records and the stripped form is itself byte-servable.
	stripped []byte
	// strippedServe is the byte-serving verdict for stripped, derived the
	// same way as wireServe and never carrying wireHasDNSSEC.
	strippedServe wireServeFlags
	// question is the packed message's question, retained unpacked so the
	// per-hit hash-collision verification (LookupByKeyVerified) and the cold
	// compat paths never need to touch the wire.
	question dns.Question
	// cd mirrors the packed header's CD bit for compat paths that classify
	// an entry without unpacking it.
	cd bool
	// wireServe is the admission-derived byte-serving verdict; its zero
	// value keeps this entry on the Msg path. One byte, by design.
	wireServe wireServeFlags
	// compress preserves the admitted message's Compress flag. Unpack never
	// sets it, so without this a served message would always repack
	// uncompressed — invisible inside the standard chain (the edns layer
	// re-enables compression) but a behavior break for exported
	// Store/CacheEntry consumers writing responses directly.
	compress   bool
	stored     time.Time
	ttl        time.Duration
	origTTL    uint32 // Original TTL in seconds for prefetch calculation
	prefetch   atomic.Bool
	rateLimit  int            // Rate limit value (0 = no limit)
	rateLimKey uint64         // Key for shared rate limiter lookup
	ede        *dns.EDNS0_EDE // Preserved EDE information

	// scope is the ECS prefix this entry was keyed under, normalized the
	// way the key preimage folds it in (masked address; /0 and invalid
	// both mean "shared"). The hit-path verifier compares it against the
	// scope the lookup probed: the key is a 64-bit xxhash, so an entry
	// that only remembered *that* it was scoped could still be handed to
	// a different ECS audience through a collision.
	//
	// The zero value means the shared key. A scoped entry is also not
	// eligible for background refresh — the prefetch worker can't
	// resynthesise the client IP a scoped query implied, so a refresh
	// would store the wrong audience's answer under the scoped key.
	// PrefetchEligible() reflects this.
	scope netip.Prefix

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
	rem, leaseRem := e.remainingBounds(now)
	if !e.cutUntil.IsZero() {
		if leaseRem < rem {
			rem = leaseRem
		}
	}
	return rem
}

// remainingBounds returns the two independent lifetimes that remaining folds
// together: the answer TTL and the delegation lease. A zero cutUntil is
// unbounded and therefore returns zero for leaseRemaining; callers must check
// cutUntil before interpreting that value as an expired lease.
func (e *CacheEntry) remainingBounds(now time.Time) (ttlRemaining, leaseRemaining time.Duration) {
	ttlRemaining = e.ttl - now.Sub(e.stored)
	if !e.cutUntil.IsZero() {
		leaseRemaining = e.cutUntil.Sub(now)
	}
	return ttlRemaining, leaseRemaining
}

// NewCacheEntry creates a new cache entry from a DNS message.
func NewCacheEntry(msg *dns.Msg, ttl time.Duration, rateLimit int) *CacheEntry {
	return NewCacheEntryWithKey(msg, ttl, rateLimit, 0)
}

// NewScopedCacheEntry creates a cache entry that's been keyed under
// an ECS scope. scope MUST be the prefix the entry's key was computed
// from — the hit-path verifier compares the two exactly, so an entry
// admitted under a scope it does not carry is unreachable. A /0 or
// invalid scope leaves the entry shared, matching CacheKey.Hash, which
// collapses /0 to the unscoped key.
func NewScopedCacheEntry(msg *dns.Msg, ttl time.Duration, rateLimit int, scope netip.Prefix) *CacheEntry {
	e := NewCacheEntryWithKey(msg, ttl, rateLimit, 0)
	if e == nil {
		return nil
	}
	e.scope = normalizeKeyScope(scope)
	return e
}

// scoped reports whether this entry was admitted under an ECS scope
// rather than the shared key.
func (e *CacheEntry) scoped() bool { return e.scope.IsValid() }

// PrefetchEligible reports whether the prefetch worker may refresh
// this entry. Scoped entries are skipped because the worker has no
// client IP, so a refresh would lose the ECS scope and create a
// shared-key entry instead — wrong answer for the wrong audience.
func (e *CacheEntry) PrefetchEligible() bool { return !e.scoped() }

// NewCacheEntryWithKey creates a new cache entry with a specific key for rate
// limiting. A message that cannot be packed returns nil — such a response was
// never servable on the wire, so declining to cache it is the safe outcome.
func NewCacheEntryWithKey(msg *dns.Msg, ttl time.Duration, rateLimit int, key uint64) *CacheEntry {
	// Assemble the storable view and filter out OPT records (matching V1
	// behavior): OPT is per-client hop metadata the serve path rebuilds.
	msgCopy := new(dns.Msg)
	msgCopy.MsgHdr = msg.MsgHdr
	msgCopy.Question = msg.Question
	msgCopy.Answer = msg.Answer
	msgCopy.Ns = msg.Ns

	var ede *dns.EDNS0_EDE

	// Filter Extra section to remove OPT records but preserve EDE
	if len(msg.Extra) > 0 {
		extra := make([]dns.RR, 0, len(msg.Extra))
		for _, rr := range msg.Extra {
			if opt, ok := rr.(*dns.OPT); ok {
				// Extract EDE from OPT record if present. By value: the
				// long-lived entry must not alias an option inside the
				// caller's live message.
				for _, option := range opt.Option {
					if e, ok := option.(*dns.EDNS0_EDE); ok {
						private := *e
						ede = &private
						break
					}
				}
			} else {
				extra = append(extra, rr)
			}
		}
		msgCopy.Extra = extra
	}

	// Name compression keeps the stored form smaller than the upstream wire.
	// PackClone packs into pooled scratch and returns an exact-size copy:
	// the compression dictionary and the oversized pack buffer the library
	// allocated per admission are pooled away, and the entry — long-lived —
	// retains only the bytes it serves.
	msgCopy.Compress = true
	wire, err := wirepack.PackClone(msgCopy)
	if err != nil {
		return nil
	}

	entry := &CacheEntry{
		wire: wire,
		// Keep the monotonic clock reading. Converting to UTC strips it and
		// would let a backward wall-clock adjustment extend both the TTL and
		// an inherited delegation cut.
		stored:     time.Now(),
		ttl:        ttl,
		origTTL:    uint32(ttl.Seconds()),
		rateLimit:  rateLimit,
		rateLimKey: key,
		ede:        ede,
		cd:         msg.CheckingDisabled,
		compress:   msg.Compress,
	}
	if len(msg.Question) > 0 {
		entry.question = msg.Question[0]
	}
	entry.wireServe = prepareWireServe(wire)
	entry.prepareStripped(msgCopy)

	return entry
}

// prepareStripped packs the body a client without DO receives: the same
// message with its DNSSEC records removed. Most clients do not set DO, and
// most of what a validating resolver caches is signed, so without this the
// commonest hit of all decodes the stored bytes into a message — turning
// every signature into a base64 string on the way — only to drop those very
// records and pack what is left.
//
// The stripped body is packed here, once per entry, rather than derived from
// the stored bytes per hit: name compression makes the sections' offsets
// interdependent, so records cannot be cut out of a packed message without
// re-encoding it.
func (e *CacheEntry) prepareStripped(msgCopy *dns.Msg) {
	// An explicit RRSIG question keeps its signatures for any DO —
	// ClearDNSSEC would return the message unchanged, so the stripped
	// body would only duplicate the stored one.
	if e.wireServe&wireHasDNSSEC == 0 || e.question.Qtype == dns.TypeRRSIG {
		return
	}

	// ClearDNSSEC replaces the sections it filters rather than editing them,
	// so the stored message's own arrays are unaffected by this copy — and
	// the body is stripped by exactly the function the Msg path uses, which
	// is what keeps the two answers identical.
	stripped := *msgCopy
	dnsutil.ClearDNSSEC(&stripped)
	stripped.Compress = true

	// Pooled scratch, exact-size result — the second per-admission pack,
	// same treatment as the first.
	body, err := wirepack.PackClone(&stripped)
	if err != nil {
		return
	}

	flags := prepareWireServe(body)
	// Byte serving is all-or-nothing per body: an entry whose stripped form
	// is not servable simply keeps the Msg path for its DO=0 hits.
	const ready = wireEligible | wireChaseSafe
	if flags&ready != ready || flags&wireHasDNSSEC != 0 {
		return
	}
	e.stripped, e.strippedServe = body, flags
}

// (*CacheEntry).ToMsg toMsg creates a response message with updated TTLs.
func (e *CacheEntry) ToMsg(req *dns.Msg) *dns.Msg {
	now := time.Now()
	remainingTTL := e.remaining(now)

	if remainingTTL <= 0 {
		return nil
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(e.wire); err != nil {
		// The wire was produced by our own Pack at admission; failure here
		// means corruption, and a miss re-resolves safely.
		return nil
	}
	// Unpack leaves Compress unset; restore the admitted flag so direct
	// writers repack exactly as the parsed representation did.
	resp.Compress = e.compress
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

// storedMsg unpacks the retained wire form without any serve-time shaping.
// Inspection paths (tests, future debug surfaces) use it; the hit path goes
// through ToMsg.
func (e *CacheEntry) storedMsg() *dns.Msg {
	if e == nil {
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(e.wire); err != nil {
		return nil
	}
	msg.Compress = e.compress
	return msg
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

// normalizeKeyScope reduces a scope to the single form the key preimage
// stands for, so that the value an entry carries and the value a lookup
// probes with can be compared for equality: /0 and invalid both mean the
// shared key (Hash routes them to cache.Key), and the host bits below the
// prefix length are never part of the preimage.
func normalizeKeyScope(scope netip.Prefix) netip.Prefix {
	if !scope.IsValid() || scope.Bits() == 0 {
		return netip.Prefix{}
	}
	return scope.Masked()
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
	ServeStale  bool
	// ServeStaleMaxTTL is measured from the admitted answer TTL's expiry.
	// Zero leaves cutUntil as the only stale lifetime bound.
	ServeStaleMaxTTL time.Duration

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
	if cc.ServeStaleMaxTTL < 0 {
		return errors.New("serve-stale maximum TTL cannot be negative")
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
