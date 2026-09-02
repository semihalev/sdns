package cache

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
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

	// sidecar is policy state stamped beside the immutable entry — the
	// same shape as the prefetch claim above: a mutable atomic the entry
	// carries without ever being copied. The cache never reads its Value;
	// it is stamped at admission by the wired evaluator and handed to the
	// wire-hit gate at serve time. nil means unevaluated — unknown, never
	// clean (middleware.Sidecar's contract).
	sidecar atomic.Pointer[middleware.Sidecar]
}

// Sidecar returns the entry's stamped policy state; nil means the entry
// was never evaluated.
func (e *CacheEntry) Sidecar() *middleware.Sidecar {
	return e.sidecar.Load()
}

// CompareAndStampSidecar installs next if the entry still carries prev —
// the restamp a serve performs when it finds a stale generation. The
// generation lives inside the opaque value; the CAS only guarantees no
// concurrent restamp is silently overwritten.
func (e *CacheEntry) CompareAndStampSidecar(prev, next *middleware.Sidecar) bool {
	return e.sidecar.CompareAndSwap(prev, next)
}

// remaining returns the entry's effective remaining lifetime at now:
// the stored TTL minus elapsed time, further bounded by cutUntil. It says
// whether the entry may be served; servedTTL says what TTL to write.
func (e *CacheEntry) remaining(now time.Time) time.Duration {
	rem, leaseRem := e.remainingBounds(now)
	if !e.cutUntil.IsZero() {
		if leaseRem < rem {
			rem = leaseRem
		}
	}
	return rem
}

// servedTTL is the TTL a hit writes at now: servedSeconds of the entry's
// remaining lifetime, with one exception. When the delegation lease is the
// binding bound it is a security bound, the parent's grant
// (GHSA-mqfw-f48p-2vc8), and its last fraction of a second is not rounded up
// into a whole second the parent never granted: the answer goes out with a
// TTL of zero, nothing to keep. The round-up is the entry's own concession
// about its own lifetime. A one-second lease stays servable for its second
// this way, where declining the hit instead made it unservable from the
// moment it was stored; the stale path, which RFC 8767 forbids a zero,
// declines the same remainder.
func (e *CacheEntry) servedTTL(now time.Time) uint32 {
	rem, leaseRem := e.remainingBounds(now)
	if !e.cutUntil.IsZero() && leaseRem < rem {
		if leaseRem < time.Second {
			return 0
		}
		rem = leaseRem
	}
	return servedSeconds(rem)
}

// servedSeconds is the TTL written into an answer this cache is serving.
//
// A hit never carries a TTL of zero: that tells the client not to reuse an
// answer the cache is reusing, and RFC 2308 §5 rules it out for a denial
// outright. The last fraction of a second therefore rounds up to one.
//
// Retiring such an entry instead was tried and does not work. An entry admitted
// for exactly one second, which is what a zone publishing a one-second SOA
// MINIMUM asks for, is already under a second by the time anything looks it up,
// so the rule that refuses to serve it also makes every one-second lifetime
// uncacheable. Honouring the zone's one second and then never using it is not a
// stricter reading, it is a pointless one.
//
// What is left is the granularity of the wire format: a client can hold the
// last fraction of a second past the bound, because a DNS TTL cannot express
// less. This cache stops serving at the bound exactly. That concession is
// the entry's own to make, about its own lifetime; servedTTL withholds it
// from a delegation lease, so a client is never rounded past the parent's
// grant.
func servedSeconds(remaining time.Duration) uint32 {
	if remaining <= 0 {
		return 0
	}
	if secs := remaining / time.Second; secs > 0 {
		return uint32(secs) //nolint:gosec // G115 - bounded by MaxCacheTTL
	}
	return 1
}

// remainingBounds returns the two independent lifetimes that remaining folds
// together: the answer TTL and the delegation lease. A zero cutUntil is
// unbounded and therefore returns zero for leaseRemaining; callers must check
// cutUntil before interpreting that value as an expired lease.
func (e *CacheEntry) remainingBounds(now time.Time) (ttlRemaining, leaseRemaining time.Duration) {
	// Both are exact. Quantising the age here to whole seconds was tried and
	// is wrong twice over: it lets an answer outlive the delegation lease,
	// which is a security bound (GHSA-mqfw-f48p-2vc8), and it keeps an entry
	// whose own lifetime is under a second alive for a full one. Whether the
	// entry is alive is a question about time; what TTL to write is a question
	// about the wire format, and servedSeconds answers that one.
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
	return newScopedCacheEntryAt(msg, ttl, rateLimit, scope, time.Now())
}

func newScopedCacheEntryAt(msg *dns.Msg, ttl time.Duration, rateLimit int, scope netip.Prefix, now time.Time) *CacheEntry {
	e := newCacheEntryAt(msg, ttl, rateLimit, 0, now)
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
// limiting. It returns nil for a message that cannot be packed — such a
// response was never servable on the wire, so declining to cache it is the
// safe outcome — and for an explicit RRSIG answer the stored view would
// thin, which a hit may not answer with fewer signatures than the first
// response did. Callers treat nil as "not cacheable" either way.
func NewCacheEntryWithKey(msg *dns.Msg, ttl time.Duration, rateLimit int, key uint64) *CacheEntry {
	return newCacheEntryAt(msg, ttl, rateLimit, key, time.Now())
}

// newCacheEntryAt is NewCacheEntryWithKey anchored at now: the instant the
// entry is stored at, the one its ttl was measured at, and the one every
// decision about what the entry may carry is taken at. One clock, so a
// lifetime and the signatures judged against it never disagree by the
// moment between two readings. Monotonic, never UTC-converted: a backward
// wall-clock step must not extend the entry.
func newCacheEntryAt(msg *dns.Msg, ttl time.Duration, rateLimit int, key uint64, now time.Time) *CacheEntry {
	// Assemble the storable view and filter out OPT records (matching V1
	// behavior): OPT is per-client hop metadata the serve path rebuilds.
	msgCopy := new(dns.Msg)
	msgCopy.MsgHdr = msg.MsgHdr
	msgCopy.Question = msg.Question
	// The entry keeps only the signatures it vouches for. Every hit path
	// serves these bytes with each record's TTL set to the entry's remaining
	// lifetime, and that lifetime is bounded by the usable signatures alone
	// (dnsutil.CalculateCacheTTL): a signature outside its validity period
	// — a rollover's lapsed sibling, or one whose inception has not arrived
	// — was received with whatever TTL it carried and would be handed out
	// on the next hit with the entry's, a zero returned as an hour, and the
	// not-yet-valid one revived once its inception passed. The uncached
	// first response still carries them as the authority sent them.
	msgCopy.Answer = storableRecords(msg.Answer, now)
	msgCopy.Ns = storableRecords(msg.Ns, now)

	// An explicit RRSIG question asks for the signatures themselves, and
	// the lapsed and pending ones are as much the answer as the live one
	// (RFC 4035 §3.2.1): the record is the data, so a hit may not answer
	// with fewer than the first response did. If storing would drop any,
	// the answer is not stored.
	if len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeRRSIG &&
		(len(msgCopy.Answer) != len(msg.Answer) || len(msgCopy.Ns) != len(msg.Ns)) {
		return nil
	}

	// An entry never carries AD over data whose signatures have lapsed
	// (RFC 4035 §3.2.3). The writer clears the bit on the response it sends,
	// but it does so after the stores, and an entry that kept the bit would
	// hand it back on every later hit. Normalised here, on the storable view
	// and before packing, so no admission path can miss it. Checked only
	// when the bit is set: unsigned and unvalidated data pays nothing.
	if msgCopy.AuthenticatedData && dnsutil.HasExpiredSignatures(msg, now) {
		msgCopy.AuthenticatedData = false
	}

	var ede *dns.EDNS0_EDE
	if len(msg.Extra) > 0 {
		msgCopy.Extra, ede = storableAdditional(msg.Extra, now, ttl)
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
		// The anchoring instant, monotonic reading kept. Converting to UTC
		// strips it and would let a backward wall-clock adjustment extend
		// both the TTL and an inherited delegation cut.
		stored:     now,
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
	// The flag already leaves out the type an explicit RRSIG, NSEC or NSEC3
	// question asked for: without it ClearDNSSEC would return the message
	// unchanged, and the stripped body would only duplicate the stored one.
	if e.wireServe&wireHasDNSSEC == 0 {
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
	ttl := e.servedTTL(now)
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

// (TTLManager).Bound applies the upper bound to a lifetime that has already
// been decided, and nothing else.
//
// It deliberately carries no floor. dnsutil.CalculateCacheTTL is the only place
// that knows what may not be lifted: a signature with two seconds left, an SOA
// that granted one. A second floor here cannot see any of that, and it does not
// merely duplicate the first one, it undoes it. A signed answer correctly
// bounded to two seconds on the way in was admitted for five, and served after
// its signature had lapsed.
//
// The rule this leaves is simple enough to keep: the lower bound is decided
// once, where the evidence is, and every layer after it may only shorten.
func (tm TTLManager) Bound(msgTTL time.Duration) time.Duration {
	if msgTTL < 0 {
		return 0
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

// storableRecords returns records without the signatures that are outside
// their validity period at now. The common shape, nothing to drop, passes
// the caller's slice through untouched — this runs on every admission, and
// a response carries a lapsed or not-yet-valid signature only mid-rollover.
func storableRecords(records []dns.RR, now time.Time) []dns.RR {
	drop := 0
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok && !sig.ValidityPeriod(now) {
			drop++
		}
	}
	if drop == 0 {
		return records
	}
	kept := make([]dns.RR, 0, len(records)-drop)
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok && !sig.ValidityPeriod(now) {
			continue
		}
		kept = append(kept, rr)
	}
	return kept
}

// storableAdditional returns the additional section as the entry stores it:
// without the OPT, whose EDE is returned by value, and with every signed
// RRset either kept with its signatures or removed with them.
//
// The additional section bounds neither AD nor the entry's lifetime (RFC
// 4035 §3.2.3; nothing validates it), and every hit serves each record with
// that lifetime as its TTL. So a signature here can be kept only when it
// permits at least the entry's lifetime — a live one carrying a shorter TTL
// would be handed out inflated, and one outside its validity period would be
// handed out at all. A signed RRset does not go on without its signature,
// either: RFC 4035 §3.1.1 has the two travel together, and a mail exchanger's
// address that arrived signed and was served bare on the next hit is a
// different answer. An RRset none of whose signatures can be kept leaves with
// them; a lapsed sibling beside a signature that can be kept leaves alone, as
// it does in the answer. Unsigned records already bound the lifetime through
// their own TTLs and stay.
func storableAdditional(records []dns.RR, now time.Time, lifetime time.Duration) ([]dns.RR, *dns.EDNS0_EDE) {
	var ede *dns.EDNS0_EDE

	// honours reports whether the entry's lifetime stays within what sig
	// permits — exactly. The lifetime and this check read the same clock
	// (newCacheEntryAt), so there is no measurement gap to forgive, and a
	// served TTL rounds only at the serve point: RFC 4035 §5.3.3's ceiling
	// is not a place for tolerance, a one-second signature admitted to a
	// two-second entry was served past it whole.
	honours := func(sig *dns.RRSIG) bool {
		permits, valid := dnsutil.SignatureLifetime(sig, now)
		return valid && permits >= lifetime
	}

	// Every signature, with its verdict. Empty on the common path, an
	// unsigned additional section, and costs nothing there.
	type judged struct {
		sig  *dns.RRSIG
		kept bool
	}
	var sigs []judged
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, judged{sig: sig, kept: honours(sig)})
		}
	}
	// Names compare as DNS names, not as text: an owner spelled with an
	// escaped octet packs to the same wire name as its plain spelling, and
	// a case fold of the presentation form does not see that — a record
	// received under one spelling slipped past the TTL check made against
	// its signature under the other.
	sameName := func(a, b string) bool { return dnsname.CanonicalCompare(a, b) == 0 }
	over := func(sig *dns.RRSIG, name string, class, rrtype uint16) bool {
		return sig.TypeCovered == rrtype && sig.Hdr.Class == class && sameName(sig.Hdr.Name, name)
	}
	// condemned: a signed RRset the entry cannot carry honestly. Nothing
	// left signs it; or its signatures name more than one signer; or its
	// own records were received with less TTL than the entry's lifetime.
	//
	// The second is the delegation boundary, where the parent's NSEC over
	// the child's name and the child's apex NSEC share owner, class and
	// type (RFC 4035 §5.3.2): on the wire that is one RRset, its records
	// cannot be told apart by signer, and a live child signature was
	// carrying the parent's lapsed records with it. The third is §5.3.3's
	// other ceiling, the RRset's TTL as received: an unsigned answer takes
	// the positive floor, and a signed additional address received with a
	// one-second TTL was lifted to it and served at five. Such a tuple
	// goes whole, signatures included.
	condemned := func(name string, class, rrtype uint16) bool {
		signed, kept := false, false
		var signer string
		for _, j := range sigs {
			if !over(j.sig, name, class, rrtype) {
				continue
			}
			if signed && !sameName(signer, j.sig.SignerName) {
				return true
			}
			signed, signer = true, j.sig.SignerName
			kept = kept || j.kept
		}
		if !signed {
			return false
		}
		if !kept {
			return true
		}
		for _, rr := range records {
			h := rr.Header()
			if h.Rrtype == rrtype && h.Class == class && sameName(h.Name, name) &&
				time.Duration(h.Ttl)*time.Second < lifetime {
				return true
			}
		}
		return false
	}

	extra := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		switch r := rr.(type) {
		case *dns.OPT:
			// Extract EDE from OPT record if present. By value: the
			// long-lived entry must not alias an option inside the
			// caller's live message.
			for _, option := range r.Option {
				if e, ok := option.(*dns.EDNS0_EDE); ok {
					private := *e
					ede = &private
					break
				}
			}
			continue
		case *dns.RRSIG:
			if !honours(r) || condemned(r.Hdr.Name, r.Hdr.Class, r.TypeCovered) {
				continue
			}
		default:
			h := r.Header()
			if condemned(h.Name, h.Class, h.Rrtype) {
				continue
			}
		}
		extra = append(extra, rr)
	}
	return extra, ede
}
