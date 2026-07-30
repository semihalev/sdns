package cache

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/ecs"
	"github.com/semihalev/sdns/internal/waitgroup"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

var debugns bool

func init() {
	_, debugns = os.LookupEnv("SDNS_DEBUGNS")
}

const (
	name   = "cache"
	maxTTL = dnsutil.MaxCacheTTL
	minTTL = dnsutil.MinCacheTTL

	// maxCnameChaseDepth bounds how many nested CNAME-chase
	// invocations may happen for a single client query. The
	// additionalAnswer helper itself walks a chain of up to 10
	// hops per invocation; this counter bounds the number of
	// recursive invocations (one per nested Queryer.Query that
	// happens to return a CNAME whose target is also chased).
	// Replaces the previous !w.Internal() guard, which allowed
	// at most one level of chasing.
	maxCnameChaseDepth = 10
)

// cnameChaseDepthKeyType tags ctx with the current CNAME-chase
// depth. Sentinel pointer type so interface boxing doesn't allocate
// on each context.Value lookup.
type cnameChaseDepthKeyType struct{}

var cnameChaseDepthKey = &cnameChaseDepthKeyType{}

func cnameChaseDepth(ctx context.Context) int {
	v, _ := ctx.Value(cnameChaseDepthKey).(int)
	return v
}

func withCnameChaseDepth(ctx context.Context, depth int) context.Context {
	return context.WithValue(ctx, cnameChaseDepthKey, depth)
}

// sharedDenialBypassKey pins raw ECS and incoming CD=1 to the whole request
// tree. CNAME and DNAME follow-ups manufacture fresh DO=1 messages and can
// inherit header bits from a rewritten response; message-local checks would
// therefore let an audience-scoped or checking-disabled client consume global
// RFC 8020/8198 state on the alias target.
type sharedDenialBypassKeyType struct{}

var sharedDenialBypassKey = &sharedDenialBypassKeyType{}

func withSharedDenialBypass(ctx context.Context) context.Context {
	if sharedDenialBypass(ctx) {
		return ctx
	}
	return context.WithValue(ctx, sharedDenialBypassKey, true)
}

func sharedDenialBypass(ctx context.Context) bool {
	bypass, _ := ctx.Value(sharedDenialBypassKey).(bool)
	return bypass
}

// Cache is the cache implementation.
type Cache struct {
	positive *PositiveCache
	negative *NegativeCache
	failure  *FailureCache

	// store is the public-facing storage facade backed by the same
	// answer caches and RFC 9520 failure cache. External callers (resolver
	// sub-queries, queryer-driven prefetch, future API purge wiring)
	// route through Store; the middleware itself uses both views —
	// Store for the new API surface, direct sub-cache access for
	// the few existing answer hot paths that already have a key in hand.
	store *Store

	prefetchQueue *PrefetchQueue

	// queryer routes CNAME chase and (eventually) client-shaped
	// internal work through the sub-pipeline. Wired by sdns.go at
	// startup; nil-safe call sites guard for tests that construct
	// Cache without full startup.
	queryer middleware.Queryer
	// prefetchQueryer routes prefetch refreshes through a
	// cache-less sub-pipeline so the refresh hits the upstream
	// resolver / forwarder rather than its own stale entry.
	prefetchQueryer middleware.Queryer
	// dnssecCryptoLimiter is the resolver-owned shared concurrency gate.
	// RFC 8198 NSEC3 synthesis uses only non-blocking acquisition: failure to
	// get a slot is a cache miss, never a client-visible error.
	dnssecCryptoLimiter middleware.DNSSECCryptoLimiter

	config  CacheConfig
	metrics *CacheMetrics

	// ecsPolicy mirrors middleware/edns's policy: nil when ECS
	// forwarding is off (cache keys stay shared, today's behaviour),
	// non-nil when on (lookup probes scoped keys, insert keys by
	// the authority's SCOPE). Built once at New().
	ecsPolicy *ecs.Policy

	// Request deduplication
	wg *waitgroup.WaitGroup

	// Response writer pool
	writerPool sync.Pool

	// Compatibility fields for tests that might access these
	pcache interface{ Len() int }
	ncache interface{ Len() int }
}

// New creates a new cache.
func New(cfg *config.Config) *Cache {
	failureCfg := cfg.RecursionFirewall
	failureCfg.Normalize()

	// Build cache configuration
	cacheConfig := CacheConfig{
		Size:        cfg.CacheSize,
		Prefetch:    int(cfg.Prefetch),
		PositiveTTL: maxTTL,
		NegativeTTL: time.Duration(cfg.Expire) * time.Second,
		MinTTL:      minTTL,
		MaxTTL:      maxTTL,
		RateLimit:   cfg.RateLimit,
		ECSMaxTTL:   cfg.ECS.CacheLimitTTL.Duration,
	}

	// Validate configuration and actually apply defaults when
	// validation fails. Previously the log claimed fallback
	// behaviour that never happened — an omitted cachesize
	// passed Size=0 straight into NewPositiveCache/NewNegativeCache
	// (each got 0/2 = 0 entries), reducing the cache to one
	// entry and causing severe churn.
	if err := cacheConfig.Validate(); err != nil {
		zlog.Warn("Cache configuration validation failed, using defaults", "error", err.Error())
		if cacheConfig.Size < 1024 {
			cacheConfig.Size = 1024
		}
		if cacheConfig.Prefetch < 0 || cacheConfig.Prefetch > 90 {
			cacheConfig.Prefetch = 0
		}
		if cacheConfig.MinTTL < 0 {
			cacheConfig.MinTTL = minTTL
		}
		if cacheConfig.MaxTTL < cacheConfig.MinTTL {
			cacheConfig.MaxTTL = maxTTL
		}
	}

	// Adjust prefetch percentage
	if cacheConfig.Prefetch > 0 && cacheConfig.Prefetch < 10 {
		cacheConfig.Prefetch = 10
	}

	metrics := &CacheMetrics{}

	positive := NewPositiveCache(cacheConfig.Size/2, minTTL, maxTTL, metrics)
	negative := NewNegativeCache(cacheConfig.Size/2, minTTL, cacheConfig.NegativeTTL, metrics)
	failure, err := NewFailureCache(FailureCacheConfig{
		Size:       failureCfg.FailureCacheSize,
		InitialTTL: failureCfg.FailureCacheMinTTL.Duration,
		MaxTTL:     failureCfg.FailureCacheMaxTTL.Duration,
	})
	if err != nil {
		zlog.Warn("Failure cache configuration validation failed, using defaults", "error", err.Error())
		failure, _ = NewFailureCache(FailureCacheConfig{
			Size:       config.DefaultRecursionFirewallFailureCacheSize,
			InitialTTL: config.DefaultRecursionFirewallFailureCacheMinTTL,
			MaxTTL:     config.DefaultRecursionFirewallFailureCacheMaxTTL,
		})
	}

	c := &Cache{
		positive: positive,
		negative: negative,
		failure:  failure,

		store: NewStore(positive, negative, cacheConfig, failure),

		config:    cacheConfig,
		metrics:   metrics,
		ecsPolicy: buildCacheECSPolicy(cfg),

		wg: waitgroup.New(15 * time.Second),

		writerPool: sync.Pool{
			New: func() any {
				return &ResponseWriter{}
			},
		},
	}

	// Initialize prefetch queue if enabled
	if cacheConfig.Prefetch > 0 {
		workers := 4
		queueSize := 1000
		c.prefetchQueue = NewPrefetchQueue(workers, queueSize, metrics)
	}

	// Set compatibility fields
	c.pcache = c.positive
	c.ncache = c.negative

	// Register metrics instance for Prometheus hit rate calculation
	SetMetricsInstance(c.metrics)
	SetCacheSizeFuncs(
		c.positive.Len,
		c.negative.Len,
		c.failure.Len,
		c.store.NXDomainCutLen,
		c.store.DenialProofLen,
	)

	return c
}

// (*Cache).Name name returns middleware name.
func (c *Cache) Name() string { return name }

// buildCacheECSPolicy parses [ecs] config the same way
// middleware/edns does, so the cache and the forwarder agree on
// who is in the allow-list, what the source-prefix ceiling is, and
// what min-scope cap to apply when keying. Invalid configuration
// disables ECS-aware caching (cache falls back to shared keys for
// the affected requests); a startup log line surfaces the reason.
func buildCacheECSPolicy(cfg *config.Config) *ecs.Policy {
	c := cfg.ECS
	p, err := ecs.Build(
		c.Enabled,
		c.ForwardV4Max, c.ForwardV6Max,
		c.MinScopeV4, c.MinScopeV6,
		c.ClientNetworks,
	)
	if err != nil {
		zlog.Error("ECS-aware caching disabled: invalid [ecs] configuration",
			"error", err.Error())
		return nil
	}
	return p
}

// (*Cache).Store returns the storage facade, typed as
// middleware.Store so Cache satisfies middleware.StoreProvider for
// auto-wiring in middleware.Setup. External callers that need the
// full *Store surface can type-assert.
func (c *Cache) Store() middleware.Store { return c.store }

// (*Cache).Purge removes positive and negative cache entries for q
// under both CD=true and CD=false. Implements middleware.Purger so
// the api purge endpoint can invalidate cache state without
// synthesising a CHAOS-NULL request.
func (c *Cache) Purge(q dns.Question) {
	c.store.Purge(q)
}

// (*Cache).SetQueryer installs the Queryer used for internal
// client-shaped work (CNAME chase on cache writeback, future DNAME
// target lookup from the resolver). Called once from sdns.go
// startup.
func (c *Cache) SetQueryer(q middleware.Queryer) { c.queryer = q }

// (*Cache).SetPrefetchQueryer installs the Queryer used by the
// prefetch worker. The prefetch sub-pipeline excludes the cache
// middleware so a refresh reaches the upstream resolver / forwarder
// instead of returning its own about-to-expire entry.
func (c *Cache) SetPrefetchQueryer(q middleware.Queryer) { c.prefetchQueryer = q }

// SetDNSSECCryptoLimiter installs the resolver-owned gate used by optional
// NSEC3 proof lookups. Called once by middleware.Setup before publication.
func (c *Cache) SetDNSSECCryptoLimiter(limiter middleware.DNSSECCryptoLimiter) {
	c.dnssecCryptoLimiter = limiter
	if c.store != nil {
		c.store.dnssecCryptoLimiter = limiter
	}
}

// errQueryerNotWired is returned when an internal Cache lookup fires
// before sdns.go wiring has installed a Queryer. Production never
// sees this path; it exists so tests that construct a partially
// wired Cache fail with a clear error instead of a nil deref.
var errQueryerNotWired = errors.New("cache: queryer not wired")

// internalExchange routes CNAME-chase sub-queries through the
// installed Queryer.
func (c *Cache) internalExchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if c.queryer == nil {
		return nil, errQueryerNotWired
	}
	return c.queryer.Query(ctx, req)
}

// prefetchExchange routes prefetch refresh traffic through the
// prefetch sub-pipeline (cache excluded).
func (c *Cache) prefetchExchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if c.prefetchQueryer == nil {
		return nil, errQueryerNotWired
	}
	return c.prefetchQueryer.Query(ctx, req)
}

// (*Cache).ServeDNS serveDNS implements the middleware.Handler interface.
func (c *Cache) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if len(req.Question) == 0 {
		ch.Cancel()
		return
	}

	q := req.Question[0]
	requestCD := req.CheckingDisabled
	requestHasECS := hasEDNSClientSubnet(req)
	if requestCD || requestHasECS {
		ctx = withSharedDenialBypass(ctx)
	}
	requestTreeBypassesSharedDenial := sharedDenialBypass(ctx)

	// Validate query class and type
	if !c.isValidQuery(q) {
		ch.Cancel()
		return
	}

	// Handle special queries
	if c.handleSpecialQuery(ctx, ch, q) {
		return
	}

	// Check recursion desired
	if q.Name != "." && !req.RecursionDesired {
		ch.CancelWithRcode(dns.RcodeServerFailure, false)
		return
	}

	// Derive the client's ECS source prefix once and reuse it for
	// scoped lookup, dedup, and insert. Zero prefix means ECS-aware
	// caching doesn't apply (policy off, client not in allow-list,
	// or no ECS option) and the request takes today's shared-key
	// path bit-for-bit.
	clientAddr, _ := netip.AddrFromSlice(w.RemoteIP())
	if clientAddr.Is4In6() {
		clientAddr = clientAddr.Unmap()
	}
	clientScope := c.requestScope(req, clientAddr)

	// Cache key uses (name, qtype, class, CD) — same granularity
	// as the dedup key so followers release into a lookup that
	// matches what the leader wrote.
	cacheKey := CacheKey{Question: q, CD: req.CheckingDisabled}.Hash()
	dedupKey := cacheKey
	if clientScope.IsValid() {
		// Dedup at the client's source prefix so two clients in
		// different ECS scopes don't share an upstream query (their
		// answers would lose the scope distinction).
		dedupKey = CacheKey{Question: q, CD: req.CheckingDisabled, Scope: clientScope}.Hash()
	}

	// Hot path: cache check before dedup. Concurrent cache hits
	// used to take the waitgroup lock and allocate a Join
	// context/timer even when the entry was already live.
	//
	// When the request carries ECS, probe scoped keys first
	// (longest-prefix-match), then fall through to the shared key
	// so SCOPE=0 / pre-Stage-2 entries still hit. checkCache
	// records the generic Hit/Miss metric on the shared-key path;
	// scopedLookup records its own Hit on the scoped path so we
	// don't double-count or under-count. ecsLookups breaks ECS
	// requests down by which path served them — operators read it
	// to see how much of the ECS-aware code path is actually
	// carrying traffic (non-ECS lookups are already counted by
	// dns_cache_hits_total / dns_cache_misses_total).
	if clientScope.IsValid() {
		if entry, scopedKey := c.scopedLookup(q, req.CheckingDisabled, clientScope); entry != nil {
			ecsLookupHitScoped.Inc()
			if c.handleCacheHit(ctx, ch, entry, scopedKey) {
				c.metrics.Hit()
				return
			}
		}
	}
	if entry := c.checkCache(cacheKey); entry != nil {
		if clientScope.IsValid() {
			ecsLookupHitShared.Inc()
		}
		if c.handleCacheHit(ctx, ch, entry, cacheKey) {
			c.metrics.Hit()
			return
		}
	}
	if cut := c.lookupNXDomainCut(ctx, req, clientScope); cut != nil {
		if c.handleNXDomainCutHit(ctx, ch, cut) {
			c.metrics.Hit()
			nxDomainCutHits.Inc()
			return
		}
	}
	if proof, kind, zone := c.lookupDenialProof(ctx, req, clientScope); proof != nil {
		if c.handleDenialProofHit(ctx, ch, proof, kind, zone) {
			c.metrics.Hit()
			return
		}
	}
	if hit, ok := c.store.LookupFailure(req, clientScope); ok {
		c.metrics.Hit()
		failureCacheHits.Inc()
		c.handleFailureHit(ctx, ch, hit)
		return
	}
	if retryKey, ok := c.store.FailureRetryKey(req, clientScope); ok {
		dedupKey = retryKey
	}
	c.metrics.Miss()
	if clientScope.IsValid() {
		ecsLookupMiss.Inc()
	}

	// Miss. Dedup upstream work: followers wait for the leader
	// to finish, then re-check the cache — the leader may have
	// just filled it. Followers that still see a miss (leader
	// failed, or wrote a response that didn't cache) proceed
	// to run the upstream chain themselves.
	//
	// Followers do NOT call Done: they never registered as a
	// participant (Join only bumps the dup counter for the
	// leader). Calling Done from a follower would either
	// over-decrement the counter or cancel the leader's
	// context out from under them.
	//
	// Internal sub-queries (CNAME chase, DNAME target, NS lookup)
	// must skip the Join to avoid deadlock: if an outer client
	// request is the K1 leader and its chase needs K2 which lands
	// back on K1, the internal chase must not block waiting for
	// itself. BufferWriter.Internal() propagates through the
	// responseWriter wrapper; checking the writer flag here is a
	// field load instead of a ctx.Value walk on every external
	// client miss. middleware.IsInternal(ctx) remains the
	// ctx-based successor for code paths without a writer in
	// scope.
	if !w.Internal() {
		if wait := c.wg.Join(dedupKey); wait != nil {
			<-wait
			// Re-check both paths after a follower wakes up: the
			// leader may have just stored a scoped entry (a
			// shared-key check would miss it), or a SCOPE=0
			// shared entry (a scoped check alone would miss it).
			if clientScope.IsValid() {
				if entry, scopedKey := c.scopedLookup(q, req.CheckingDisabled, clientScope); entry != nil {
					if c.handleCacheHit(ctx, ch, entry, scopedKey) {
						c.metrics.Hit()
						return
					}
				}
			}
			if entry := c.checkCache(cacheKey); entry != nil {
				if c.handleCacheHit(ctx, ch, entry, cacheKey) {
					c.metrics.Hit()
					return
				}
			}
			if cut := c.lookupNXDomainCut(ctx, req, clientScope); cut != nil {
				if c.handleNXDomainCutHit(ctx, ch, cut) {
					c.metrics.Hit()
					nxDomainCutHits.Inc()
					return
				}
			}
			if proof, kind, zone := c.lookupDenialProof(ctx, req, clientScope); proof != nil {
				if c.handleDenialProofHit(ctx, ch, proof, kind, zone) {
					c.metrics.Hit()
					return
				}
			}
			if hit, ok := c.store.LookupFailure(req, clientScope); ok {
				c.metrics.Hit()
				failureCacheHits.Inc()
				c.handleFailureHit(ctx, ch, hit)
				return
			}
		} else {
			defer c.wg.Done(dedupKey)
		}
	}

	// Establish the request tree's ResponseMeta sink: the resolver
	// (downstream, possibly in a nested sub-pipeline sharing this
	// ctx) records the delegation-cut deadline into it, and WriteMsg
	// reads it back to bound the cache entry (GHSA-mqfw-f48p-2vc8).
	// Reuse an existing ctx meta so nested pipelines fold into the
	// outermost request's sink; otherwise back it with this chain's
	// pooled Meta field (zeroed on Chain.Reset).
	meta := middleware.ResponseMetaFrom(ctx)
	if meta == nil {
		meta = &ch.Meta
		ctx = middleware.WithResponseMeta(ctx, meta)
	}

	// Use pooled response writer. Restore via defer so a
	// downstream panic that gets recovered upstream still
	// unwraps this chain before it returns to the pool; a
	// non-deferred restore would leave the pooled Chain with
	// a stale cache wrapper pointed at freed state.
	rw := c.writerPool.Get().(*ResponseWriter)
	rw.ResponseWriter = w
	rw.cache = c
	// Stash the active ctx so WriteMsg can read the CNAME-chase
	// depth counter and thread it into additionalAnswer's
	// sub-query. The field is cleared on release so a pooled
	// writer doesn't leak a ctx reference between uses.
	rw.ctx = ctx
	rw.req = ch.Request
	rw.requestCD = requestCD
	rw.requestHasECS = requestHasECS
	rw.requestTreeBypassesSharedDenial = requestTreeBypassesSharedDenial
	// Stash the client's request scope so WriteMsg can derive
	// the insert key without re-reading the OPT (which by then
	// may have been mutated by the edns wrapper on the response).
	rw.clientScope = clientScope
	rw.meta = meta
	ch.Writer = rw
	defer func() {
		ch.Writer = w
		rw.ctx = nil
		rw.req = nil
		rw.clientScope = netip.Prefix{}
		rw.requestCD = false
		rw.requestHasECS = false
		rw.requestTreeBypassesSharedDenial = false
		rw.meta = nil
		c.writerPool.Put(rw)
	}()

	ch.Next(ctx)
}

// checkCache checks the ordinary answer caches. RFC 9520 failures use their
// own verified lookup path because they synthesize EDE 13 and must never enter
// prefetch or CNAME-chase handling.
func (c *Cache) checkCache(key uint64) *CacheEntry {
	if entry, ok := c.store.LookupByKey(key); ok {
		return entry
	}
	return nil
}

// requestScope derives the client's ECS source prefix for cache
// keying, returning the zero prefix when ECS-aware caching shouldn't
// apply to this request (policy off, client not in allow-list, no
// ECS option, malformed option). Uses the (already-clamped) ECS
// source the edns middleware preserved on req.Extra rather than
// re-clamping from the writer's RemoteIP — keeps lookup and insert
// keying agreed on a single derivation.
func (c *Cache) requestScope(req *dns.Msg, client netip.Addr) netip.Prefix {
	if c.ecsPolicy == nil || !c.ecsPolicy.Allows(client) {
		return netip.Prefix{}
	}
	opt := req.IsEdns0()
	if opt == nil {
		return netip.Prefix{}
	}
	for _, o := range opt.Option {
		sub, ok := o.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(sub.Address)
		if !ok {
			return netip.Prefix{}
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		p, err := addr.Prefix(int(sub.SourceNetmask))
		if err != nil {
			return netip.Prefix{}
		}
		return p
	}
	return netip.Prefix{}
}

func hasEDNSClientSubnet(req *dns.Msg) bool {
	if req == nil {
		return false
	}
	opt := req.IsEdns0()
	if opt == nil {
		return false
	}
	for _, option := range opt.Option {
		if _, ok := option.(*dns.EDNS0_SUBNET); ok {
			return true
		}
	}
	return false
}

// scopedLookup probes the cache for the longest scope match that
// covers `clientPrefix`. Returns the entry + the key it was found
// under, or (nil, 0) on miss. The shared-key fallback is the
// caller's responsibility — a scoped probe that misses should still
// try the unscoped key in case the authority returned SCOPE=0
// (cached shared) or the entry predates Stage 2.
//
// Iteration runs from the client's source bits down to /1. The
// upper bound is the client's own prefix because a stored prefix
// narrower than the client's address could never contain it. The
// lower bound is /1 because ClampScope allows arbitrarily-broad
// response scopes (min_scope is a *storage* floor — refuse to
// store anything narrower — not a *lookup* floor): a /24 source
// with a /20 SCOPE response stores an entry at /20, and a later
// /24 query from the same client has to probe /20 to find it.
// Probing the unscoped /0 key would duplicate the shared-key
// check the caller does after this returns; we stop at /1.
//
// Worst case ~32 probes for IPv4 (one per bit-length 1..32) and
// ~128 for IPv6. Each probe is one hash compute + one map lookup
// — ~100 ns total — well below the cost of an upstream lookup
// or a single GC sweep.
func (c *Cache) scopedLookup(q dns.Question, cd bool, clientPrefix netip.Prefix) (*CacheEntry, uint64) {
	if !clientPrefix.IsValid() {
		return nil, 0
	}
	for bits := clientPrefix.Bits(); bits >= 1; bits-- {
		scope, err := clientPrefix.Addr().Prefix(bits)
		if err != nil {
			continue
		}
		key := CacheKey{Question: q, CD: cd, Scope: scope}.Hash()
		if entry, ok := c.store.LookupByKey(key); ok {
			return entry, key
		}
	}
	return nil, 0
}

// lookupNXDomainCut checks the RFC 8020 subtree index after an exact answer
// miss and before RFC 9520 failure state. CD=1 intentionally bypasses local
// synthesis. ECS requests also bypass P4: a signed split-horizon denial can be
// audience-specific, and P4 has no per-scope proof index. Failing open to
// ordinary resolution is safer than sharing one audience's subtree cut.
func (c *Cache) lookupNXDomainCut(
	ctx context.Context,
	req *dns.Msg,
	clientScope netip.Prefix,
) *nxDomainCutEntry {
	if req == nil || len(req.Question) == 0 ||
		req.CheckingDisabled || clientScope.IsValid() ||
		sharedDenialBypass(ctx) {
		return nil
	}
	entry, _ := c.store.LookupNXDomainCut(req)
	return entry
}

// lookupDenialProof checks the RFC 8198 index after the exact-answer and RFC
// 8020 cut paths, but before shared failure state. Like P4, the proof index is
// intentionally global rather than ECS-scoped, so any raw ECS option is a
// conservative miss even when policy did not derive a usable client scope.
// NSEC3 hashing gets a fresh optional-work budget for this lookup and uses the
// resolver-owned non-blocking crypto gate; saturation is only a cache miss.
func (c *Cache) lookupDenialProof(
	ctx context.Context,
	req *dns.Msg,
	clientScope netip.Prefix,
) (*dns.Msg, middleware.ValidatedNegativeProofKind, string) {
	if req == nil || len(req.Question) != 1 ||
		req.CheckingDisabled || clientScope.IsValid() ||
		hasEDNSClientSubnet(req) || sharedDenialBypass(ctx) {
		return nil, middleware.ValidatedNegativeProofUnknown, ""
	}
	msg, kind, zone, ok := c.store.LookupDenialProof(
		req,
		newDenialProofWork(ctx, c.dnssecCryptoLimiter),
	)
	if !ok {
		return nil, middleware.ValidatedNegativeProofUnknown, ""
	}
	return msg, kind, zone
}

func (c *Cache) handleNXDomainCutHit(
	ctx context.Context,
	ch *middleware.Chain,
	entry *nxDomainCutEntry,
) bool {
	resp := entry.response(ch.Request)
	if resp == nil {
		return false
	}

	// A cut hit is locally authenticated state, so it can safely become the
	// terminal proof source when an enclosing CNAME/DNAME response explicitly
	// propagates its exact-response provenance.
	middleware.MarkValidatedNegativeProofResponse(ctx, resp, middleware.ValidatedNegativeProof{
		Subject:    entry.deniedName,
		Zone:       entry.zone,
		Kind:       entry.proofKind,
		Aggressive: true,
	})
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
	return true
}

func (c *Cache) handleDenialProofHit(
	ctx context.Context,
	ch *middleware.Chain,
	resp *dns.Msg,
	kind middleware.ValidatedNegativeProofKind,
	zone string,
) bool {
	if resp == nil || len(resp.Question) != 1 ||
		(kind != middleware.ValidatedNegativeProofNSEC &&
			kind != middleware.ValidatedNegativeProofNSEC3) {
		return false
	}

	// Exact response identity makes a synthesized terminal proof safe to
	// propagate through an enclosing CNAME/DNAME chase. It does not grant
	// trust to copies or unrelated negative messages in the same request.
	middleware.MarkValidatedNegativeProofResponse(ctx, resp, middleware.ValidatedNegativeProof{
		Subject:    resp.Question[0].Name,
		Zone:       zone,
		Kind:       kind,
		Aggressive: true,
	})
	observeAggressiveNegativeHit(kind, resp.Rcode)
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
	return true
}

func (c *Cache) handleFailureHit(ctx context.Context, ch *middleware.Chain, hit FailureHit) {
	resp := hit.Response(ch.Request)
	if meta := middleware.ResponseMetaFrom(ctx); meta != nil {
		release := meta.MarkCachedFailureResponse(resp)
		defer release()
	}
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

// handleCacheHit processes a cache hit.
func (c *Cache) handleCacheHit(ctx context.Context, ch *middleware.Chain, entry *CacheEntry, key uint64) bool {
	w := ch.Writer
	req := ch.Request

	// Full-key verification (defends against xxhash64 key collisions).
	// The cache key is a non-cryptographic 64-bit hash of the query
	// preimage, so a collision — accidental, or attacker-searched on a
	// chosen qname — would otherwise serve one query's answer to another.
	// Returning false treats it as a miss so the chain resolves normally.
	// This is the single chokepoint for every hit (scoped and shared).
	if len(req.Question) == 0 || !entryMatchesQuestion(entry, req.Question[0]) {
		return false
	}

	// Rate limiting applies to external client queries only.
	// Internal sub-queries (CNAME chase, DNAME target, NS lookup)
	// carry BufferWriter.Internal()==true via the responseWriter
	// propagation; cancelling a rate-limited cache hit mid-chase
	// would leave the outer client with a partial CNAME answer.
	// Writer-flag check is a field load vs middleware.IsInternal's
	// ctx.Value walk, kept on the hot path for throughput;
	// middleware.IsInternal(ctx) remains available for code paths
	// without a writer in scope.
	limiter := entry.GetRateLimiter()
	if !w.Internal() && limiter != nil && !limiter.Allow() {
		ch.Cancel()
		return true
	}

	// Check if prefetch is needed. The prefetch claim (CAS on
	// entry.prefetch) must be released if Add drops the
	// request, otherwise the hot entry stays with
	// prefetch=true and ShouldPrefetch returns false until an
	// unrelated expiry or replacement clears it — prefetch
	// would silently disable itself for that key.
	//
	// PrefetchEligible() gates scoped entries out: the prefetch
	// worker has no client IP, so a refresh would forward without
	// ECS and create a shared-key entry under the scoped key —
	// wrong audience, wrong answer. Scoped entries just expire.
	if c.prefetchQueue != nil && entry.PrefetchEligible() && entry.ShouldPrefetch(c.config.Prefetch) {
		if entry.prefetch.CompareAndSwap(false, true) {
			if !c.prefetchQueue.Add(PrefetchRequest{
				Request: req.Copy(),
				Key:     key,
				Cache:   c,
				Entry:   entry,
			}) {
				entry.prefetch.Store(false)
			}
		}
	}

	// Build response from cache
	msg := entry.ToMsg(req)
	if msg == nil {
		// Entry expired between check and use
		return false
	}

	// Resolve CNAME chains if needed (matching V1 behavior).
	// The depth counter bounds nested chases across the Queryer
	// boundary: each additionalAnswer invocation increments the
	// counter so an inner cache hit on a further CNAME stops
	// chasing once the chain passes maxCnameChaseDepth. Replaces
	// the pre-Phase-3d !w.Internal() guard.
	if depth := cnameChaseDepth(ctx); depth < maxCnameChaseDepth {
		msg = c.additionalAnswer(withCnameChaseDepth(ctx, depth+1), msg)
	}

	_ = w.WriteMsg(msg)
	ch.Cancel()
	return true
}

// isValidQuery checks if the query is valid.
func (c *Cache) isValidQuery(q dns.Question) bool {
	if v := dns.ClassToString[q.Qclass]; v == "" {
		return false
	}
	if v := dns.TypeToString[q.Qtype]; v == "" {
		return false
	}
	return true
}

// handleSpecialQuery handles CHAOS and other special queries.
// Cache invalidation previously flowed through here via a
// base64-encoded CHAOS NULL request dispatched by
// dnsutil.ExchangeInternal; that path retired alongside
// ExchangeInternal itself — api/api.go now calls Cache.Purge
// directly via middleware.Pipeline.Purgers(). Only the debug-ns
// HINFO pass-through remains.
func (c *Cache) handleSpecialQuery(ctx context.Context, ch *middleware.Chain, q dns.Question) bool {
	if debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO {
		ch.Next(ctx)
		return true
	}
	return false
}

// (*Cache).Stop stop gracefully shuts down the cache.
func (c *Cache) Stop() {
	if c.prefetchQueue != nil {
		c.prefetchQueue.Stop()
	}
	if c.failure != nil {
		c.failure.Stop()
	}
	if c.store != nil {
		c.store.Stop()
	}
}

// (*Cache).Set set adds a new element to the cache. Provided for API
// compatibility (prefetch worker, plugin callers). Internally goes
// through Store; the entry is constructed with origTTL adjusted to
// the real upstream TTL so subsequent prefetch decisions don't
// miscalculate from the post-Calculate (clamped) value.
func (c *Cache) Set(key uint64, msg *dns.Msg) {
	if len(msg.Question) == 0 {
		return
	}

	filtered := filterCacheableAnswer(msg)
	mt, _ := dnsutil.ClassifyResponse(filtered, time.Now().UTC())
	if mt == dnsutil.TypeServerFailure {
		c.store.RecordFailure(filtered, netip.Prefix{}, FailureProvenance("response"))
		return
	}
	msgTTL := dnsutil.CalculateCacheTTL(filtered, mt)

	ttl := c.positive.ttl.Calculate(msgTTL)

	entry := NewCacheEntryWithKey(filtered, ttl, c.config.RateLimit, key)
	if ttl > 0 {
		entry.origTTL = uint32(ttl.Seconds())
	}

	c.store.SetEntryWithKey(key, entry, mt)
}

// (*Cache).Stats stats returns cache statistics.
func (c *Cache) Stats() map[string]any {
	hits, misses, evictions, prefetches := c.metrics.Stats()

	return map[string]any{
		"hits":               hits,
		"misses":             misses,
		"evictions":          evictions,
		"prefetches":         prefetches,
		"positive_size":      c.store.PositiveLen(),
		"negative_size":      c.store.NegativeLen(),
		"failure_size":       c.store.FailureLen(),
		"nxdomain_cut_size":  c.store.NXDomainCutLen(),
		"denial_proof_size":  c.store.DenialProofLen(),
		"denial_proof_zones": c.store.DenialProofZones(),
		"denial_proof_bytes": c.store.DenialProofBytes(),
		"hit_rate": func() float64 {
			total := float64(hits + misses)
			if total == 0 {
				return 0
			}
			return float64(hits) / total * 100
		}(),
	}
}

// ResponseWriter is the response writer for cache.
type ResponseWriter struct {
	middleware.ResponseWriter
	cache *Cache
	// ctx carries the active request context so WriteMsg can read
	// the CNAME-chase depth counter and thread it into
	// additionalAnswer's sub-query. Set by Cache.ServeDNS when the
	// writer is pulled from the pool; cleared on defer.
	ctx context.Context
	// req retains the original client EDNS capabilities so a local
	// recursion-work failure can carry its policy EDE even when the
	// downstream response omitted OPT.
	req *dns.Msg
	// clientScope is the prefix derived from the request's ECS
	// option (already clamped by the edns middleware to the policy
	// ceiling). Zero value when ECS doesn't apply, in which case
	// WriteMsg falls back to the unscoped insert path bit-for-bit
	// — that's how pre-Stage-2 traffic and SCOPE=0 responses keep
	// the same cache shape they had before.
	clientScope netip.Prefix
	// Immutable snapshots captured before downstream middleware can mutate
	// the request. Shared authenticated-denial state is never published from
	// checking-disabled or audience-scoped traffic.
	requestCD                       bool
	requestHasECS                   bool
	requestTreeBypassesSharedDenial bool
	// meta is the request tree's ResponseMeta sink, stashed by
	// Cache.ServeDNS. By the time WriteMsg runs, the resolver
	// downstream has folded the delegation-cut deadline into it;
	// the insert bounds the entry with that deadline. Nil when the
	// writer is used outside ServeDNS.
	meta *middleware.ResponseMeta
}

// (*ResponseWriter).WriteMsg writeMsg implements the ResponseWriter interface.
func (w *ResponseWriter) WriteMsg(res *dns.Msg) error {
	if res.Truncated || len(res.Question) == 0 {
		return w.ResponseWriter.WriteMsg(res)
	}

	q := res.Question[0]

	// Skip special queries
	if (debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO) ||
		(q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL) {
		return w.ResponseWriter.WriteMsg(res)
	}

	ctx := w.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Resolution failures live in the dedicated RFC 9520 cache. They bypass
	// ordinary CacheEntry handling entirely: no CNAME chase, no prefetch, no
	// RR TTL, and no replay of an upstream EDE. The first response is still
	// written verbatim (or with the local work-limit EDE); only a later cache
	// hit is synthesized as EDE 13.
	mt, _ := dnsutil.ClassifyResponse(res, time.Now().UTC())
	if mt == dnsutil.TypeServerFailure {
		out := res
		if res.Rcode == dns.RcodeServerFailure && middleware.RecursionWorkEnforcementError(ctx) != nil {
			out = w.recursionWorkFailure(res)
		}
		if cacheableResolutionFailure(ctx, out) {
			w.cache.store.RecordFailure(out, w.clientScope, FailureProvenance("response"))
		}
		return w.ResponseWriter.WriteMsg(out)
	}

	// Complete any synchronous CNAME chase before reading ResponseMeta and
	// publishing the cache entry. A target leg can cross a different (shorter)
	// delegation cut; storing first would bind the outer CNAME only to its own
	// longer cut and violate the request-tree "shortest cut wins" invariant.
	// filterCacheableAnswer below still retains only records belonging to the
	// original question, so this does not merge the target RRset into the outer
	// cache entry.
	if depth := cnameChaseDepth(ctx); depth < maxCnameChaseDepth {
		res = w.cache.additionalAnswer(withCnameChaseDepth(ctx, depth+1), res)
	}
	if chasedType, _ := dnsutil.ClassifyResponse(res, time.Now().UTC()); chasedType == dnsutil.TypeServerFailure {
		out := res
		if res.Rcode == dns.RcodeServerFailure && middleware.RecursionWorkEnforcementError(ctx) != nil {
			out = w.recursionWorkFailure(res)
		}
		if cacheableResolutionFailure(ctx, out) {
			w.cache.store.RecordFailure(out, w.clientScope, FailureProvenance("response"))
		}
		return w.ResponseWriter.WriteMsg(out)
	}

	// Classify, filter, and store via Store. Key is derived from
	// the response's CD bit — today's behaviour and the contract
	// the cache dedup leader and follower agree on.
	//
	// When the request carried an ECS scope this writer was set up
	// to understand, read the authority's SCOPE off the response.
	// SCOPE=0 ("global") means the authority's answer is suitable
	// for everyone — fall back to the shared key so any later
	// client (with or without ECS) hits the same entry. SCOPE>0
	// means the answer is geo-tailored and gets a scoped key,
	// clamped to the policy ceiling so cardinality stays bounded.
	// The delegation-cut bound for this response, folded into the
	// meta sink by the resolver while producing it. Zero (no meta,
	// or no learned delegation on the path) leaves the entry
	// unbounded — forwarder and local answers keep today's shape.
	var (
		cutUntil time.Time
		cutKey   uint64
	)
	if w.meta != nil {
		cutUntil, cutKey = w.meta.Cut()
	}

	// RFC 8020/8198 admission is an explicit resolver-to-cache trust seam.
	// Never infer it from AD=1: forwarders and plugins can supply
	// wire-authenticated-looking responses without this process having
	// validated the chain. Provenance retains the original terminal proof
	// across alias merges, so shared state contains no outer CNAME/DNAME
	// records. Check both the original request and response CD bit so an
	// intervening handler cannot turn a CD=1 request into admission.
	if !w.clientScope.IsValid() && !w.requestHasECS &&
		!w.requestTreeBypassesSharedDenial &&
		!w.requestCD && !res.CheckingDisabled {
		if negative, ok := middleware.ValidatedNegativeProofForResponse(ctx, res); ok &&
			negative.Aggressive &&
			negative.Proof != nil {
			w.cache.store.RecordDenialProof(
				negative.Proof,
				negative.Zone,
				negative.Kind,
				cutUntil,
			)
			if negative.Proof.Rcode == dns.RcodeNameError {
				w.cache.store.RecordNXDomainCut(
					negative.Proof,
					negative.Subject,
					negative.Zone,
					cutUntil,
				)
			}
		}
	}

	if w.clientScope.IsValid() {
		if respScope, ok := ecs.ReadResponseScope(res); ok {
			clamped := w.cache.ecsPolicy.ClampScope(respScope, w.clientScope)
			scopedKey := CacheKey{Question: q, CD: res.CheckingDisabled, Scope: clamped}.Hash()
			w.cache.store.SetFromResponseScoped(scopedKey, res, cutUntil, cutKey)
		} else {
			// No SCOPE in response (or SCOPE=0): authority says
			// "global"; cache shared so future non-ECS clients hit.
			key := CacheKey{Question: q, CD: res.CheckingDisabled}.Hash()
			w.cache.store.SetFromResponseWithKey(key, res, cutUntil, cutKey)
		}
	} else {
		key := CacheKey{Question: q, CD: res.CheckingDisabled}.Hash()
		w.cache.store.SetFromResponseWithKey(key, res, cutUntil, cutKey)
	}
	// This is the final downstream response observed by the cache wrapper.
	// A useful answer here means resolver/failover/forwarder recovery really
	// reached the client path, so both exact and covering zone backoff can
	// restart at the initial interval on a later failure.
	w.cache.store.resetMatchingFailures(q, res.CheckingDisabled, w.clientScope)

	return w.ResponseWriter.WriteMsg(res)
}

// cacheableResolutionFailure admits only failures that describe shared
// resolution state. Work-budget and attempt-limit rejections belong to one
// request tree; optional enrichment, cancellation, and deadline paths likewise
// cannot poison independent clients through the RFC 9520 cache.
func cacheableResolutionFailure(ctx context.Context, res *dns.Msg) bool {
	return ctx.Err() == nil &&
		!middleware.IsBestEffortRecursionWork(ctx) &&
		middleware.RecursionWorkEnforcementError(ctx) == nil &&
		middleware.RequestLocalFailureForResponse(ctx, res) == nil
}

func (w *ResponseWriter) recursionWorkFailure(fallback *dns.Msg) *dns.Msg {
	req := w.req
	if req == nil {
		req = fallback
	}
	edeCode, edeText := middleware.RecursionWorkEDE(w.ctx)
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return dnsutil.SetRcodeWithEDE(
		req,
		dns.RcodeServerFailure,
		do,
		edeCode,
		edeText,
	)
}

// filterCacheableAnswer keeps only the records directly relevant to
// the query: ones whose owner name matches Question[0].Name, plus
// DNAME records and their RRSIGs (which legitimately have a
// non-matching owner). Matches the V1 behaviour of keeping the
// cache compact and avoiding accidental retention of unrelated
// glue / additional data.
func filterCacheableAnswer(res *dns.Msg) *dns.Msg {
	if len(res.Answer) == 0 {
		return res
	}

	filtered := res.Copy()
	var answer []dns.RR

	for _, r := range filtered.Answer {
		if r.Header().Rrtype == dns.TypeDNAME ||
			strings.EqualFold(res.Question[0].Name, r.Header().Name) {
			answer = append(answer, r)
			continue
		}

		if rrsig, ok := r.(*dns.RRSIG); ok {
			if rrsig.TypeCovered == dns.TypeDNAME {
				answer = append(answer, r)
			}
		}
	}

	filtered.Answer = answer
	return filtered
}

// messagePool reduces allocations by reusing dns.Msg structs.
var messagePool = sync.Pool{
	New: func() any {
		return &dns.Msg{
			// Pre-allocate slices with typical sizes to avoid allocations
			Question: make([]dns.Question, 0, 1), // Most queries have 1 question
			Answer:   make([]dns.RR, 0, 10),      // Pre-allocate for typical responses
			Ns:       make([]dns.RR, 0, 5),       // Authority section
			Extra:    make([]dns.RR, 0, 2),       // Additional section (often OPT record)
		}
	},
}

// AcquireMsg returns an empty msg from pool with pre-allocated slices.
func AcquireMsg() *dns.Msg {
	m := messagePool.Get().(*dns.Msg)
	// Reset the message but keep the allocated slices
	m.Id = 0
	m.Response = false
	m.Opcode = 0
	m.Authoritative = false
	m.Truncated = false
	m.RecursionDesired = false
	m.RecursionAvailable = false
	m.Zero = false
	m.AuthenticatedData = false
	m.CheckingDisabled = false
	m.Rcode = 0
	m.Compress = false
	// Reset slices but keep capacity
	m.Question = m.Question[:0]
	m.Answer = m.Answer[:0]
	m.Ns = m.Ns[:0]
	m.Extra = m.Extra[:0]
	return m
}

// ReleaseMsg returns msg to pool.
func ReleaseMsg(m *dns.Msg) {
	// Clear the slices to release references but keep capacity
	for i := range m.Question {
		m.Question[i] = dns.Question{}
	}
	for i := range m.Answer {
		m.Answer[i] = nil
	}
	for i := range m.Ns {
		m.Ns[i] = nil
	}
	for i := range m.Extra {
		m.Extra[i] = nil
	}

	// Prevent memory bloat by limiting pool message size
	if cap(m.Question) <= 10 && cap(m.Answer) <= 100 && cap(m.Ns) <= 50 && cap(m.Extra) <= 20 {
		messagePool.Put(m)
	}
	// Otherwise let GC handle it to avoid memory bloat
}

// additionalAnswer implements the v1 CNAME resolution logic.
func (c *Cache) additionalAnswer(ctx context.Context, msg *dns.Msg) *dns.Msg {
	if len(msg.Question) == 0 {
		return msg
	}

	q := msg.Question[0]

	// Skip CNAME and DS queries
	if q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeDS {
		return msg
	}
	if msg.Rcode == dns.RcodeNameError {
		// RFC 6604 makes NXDOMAIN at the end of a CNAME/DNAME query
		// cycle terminal. The response already carries the target
		// denial proof; chasing an alias from its Answer again would
		// duplicate work and can no longer change the result.
		return msg
	}

	cnameReq := AcquireMsg()
	defer ReleaseMsg(cnameReq)

	cnameReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	cnameReq.CheckingDisabled = msg.CheckingDisabled

	// Check if we already have the answer we're looking for
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == q.Qtype {
			// Answer found
			return msg
		}

		if answer.Header().Rrtype == dns.TypeCNAME {
			cr := answer.(*dns.CNAME)
			if cr.Target == q.Name {
				return dnsutil.SetRcode(msg, dns.RcodeServerFailure, false)
			}
			cnameReq.SetQuestion(cr.Target, q.Qtype)
		}
	}

	cnameDepth := 10
	targets := []string{}

	if len(cnameReq.Question) > 0 {
	lookup:
		child := false
		target := cnameReq.Question[0].Name
		cnameReq.RecursionDesired = true

		// Check for loops
		if slices.Contains(targets, target) {
			return dnsutil.SetRcode(msg, dns.RcodeServerFailure, false)
		}

		targets = append(targets, target)

		respCname, err := c.internalExchange(ctx, cnameReq)
		if errors.Is(err, middleware.ErrRecursionWorkLimit) {
			edeCode, edeText := middleware.RecursionWorkErrorEDE(ctx, err)
			do := false
			if opt := msg.IsEdns0(); opt != nil {
				do = opt.Do()
			}
			return dnsutil.SetRcodeWithEDE(
				msg,
				dns.RcodeServerFailure,
				do,
				edeCode,
				edeText,
			)
		}
		if errors.Is(err, middleware.ErrResolutionAttemptLimit) {
			edeCode, edeText := dnsutil.ErrorToEDE(err)
			do := false
			if opt := msg.IsEdns0(); opt != nil {
				do = opt.Do()
			}
			out := dnsutil.SetRcodeWithEDE(
				msg,
				dns.RcodeServerFailure,
				do,
				edeCode,
				edeText,
			)
			middleware.MarkRequestLocalFailureResponse(ctx, out, err)
			return out
		}
		if err == nil && (len(respCname.Answer) > 0 || len(respCname.Ns) > 0) {
			target, child = searchAdditionalAnswer(msg, respCname)
		}

		if respCname != nil && respCname.Rcode == dns.RcodeNameError {
			// The internal query has already reached the terminal denied
			// name. Do not query a target below that cut again, and retain
			// the exact locally validated proof provenance rather than
			// attributing the NXDOMAIN to the outer alias owner.
			msg.Rcode = dns.RcodeNameError
			middleware.PropagateValidatedDenialResponse(ctx, respCname, msg)
			return msg
		}
		if respCname != nil {
			if negative, ok := middleware.ValidatedNegativeProofForResponse(ctx, respCname); ok &&
				negative.Proof != nil &&
				negative.Proof.Rcode == dns.RcodeSuccess &&
				len(negative.Proof.Answer) == 0 {
				// The target exists but lacks the requested type. Preserve
				// its authenticated terminal proof on the outer alias
				// response and stop; another chase cannot create that type.
				middleware.PropagateValidatedNegativeProofResponse(ctx, respCname, msg)
				return msg
			}
		}

		if target == q.Name {
			return dnsutil.SetRcode(msg, dns.RcodeServerFailure, false)
		}

		cnameReq.Question[0].Name = target

		cnameDepth--

		// If the chased response already supplied the final
		// answer alongside the CNAME, stop. Otherwise the next
		// goto would re-query the CNAME's target and
		// searchAdditionalAnswer would append the same final
		// record a second time — reachable now that inner
		// cache hits also run additionalAnswer (Phase 3d) and
		// short-circuit by returning the full cached chain
		// (CNAME + final A/AAAA) in one response.
		if child && cnameDepth > 0 && !respCnameHasType(respCname, q.Qtype) {
			goto lookup
		}

	}

	return msg
}

// respCnameHasType reports whether the CNAME-chase response
// already contains a record of the final qtype. Used to short-
// circuit the outer chase loop when the inner hop supplied both
// the CNAME and its target's final answer in one message —
// without this check, the outer loop would ask for the CNAME's
// target again and searchAdditionalAnswer would append the same
// final record a second time.
func respCnameHasType(res *dns.Msg, qtype uint16) bool {
	if res == nil {
		return false
	}
	for _, r := range res.Answer {
		if r.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// searchAdditionalAnswer merges the CNAME response into the original message.
func searchAdditionalAnswer(msg, res *dns.Msg) (target string, child bool) {
	if msg.AuthenticatedData && !res.AuthenticatedData {
		msg.AuthenticatedData = false
	}

	for _, r := range res.Answer {
		msg.Answer = append(msg.Answer, r)
		if r.Header().Rrtype == dns.TypeCNAME {
			cr := r.(*dns.CNAME)
			target = cr.Target
			child = true
		}
	}

	for _, r1 := range res.Ns {
		dup := false
		for _, r2 := range msg.Ns {
			if dns.IsDuplicate(r1, r2) {
				dup = true
				break
			}
		}

		if !dup {
			msg.Ns = append(msg.Ns, r1)
		}
	}

	return
}
