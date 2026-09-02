package cache

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	internalcache "github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/debugenv"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/ecs"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/internal/waitgroup"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
	"github.com/semihalev/zlog/v2"
	"golang.org/x/time/rate"
)

var debugns = debugenv.DebugNS()

const (
	name   = "cache"
	maxTTL = dnsutil.MaxCacheTTL
	minTTL = dnsutil.MinCacheTTL

	// One clean re-election lets a healthy follower recover after the first
	// expired-failure probe was rejected by a request-local budget. A second
	// request-local generation sheds the remaining cohort instead of turning
	// N followers into N sequential authority probes.
	maxFailureProbeRegroups  = 1
	failureProbeLimitEDEText = "Failure probe retry limit exceeded"

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

	// cfg supplies the forward-zone matcher. Covering denial and failure
	// state is learned from public resolution, so it must not answer for a
	// zone the operator has since pointed at its own upstreams.
	cfg *config.Config

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

	// wireHitGate is the serve half of the sidecar seam: consulted before
	// any record-bearing byte serve with the sidecar(s) the reply would be
	// built from. Wired at Setup alongside the store's evaluator; nil (no
	// policy middleware registered) costs one field check per hit.
	wireHitGate middleware.WireHitGate

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
		Size:             cfg.CacheSize,
		Prefetch:         int(cfg.Prefetch),
		PositiveTTL:      maxTTL,
		NegativeTTL:      time.Duration(cfg.Expire) * time.Second,
		MinTTL:           minTTL,
		MaxTTL:           maxTTL,
		RateLimit:        cfg.RateLimit,
		ECSMaxTTL:        cfg.ECS.CacheLimitTTL.Duration,
		ServeStale:       cfg.ServeStale,
		ServeStaleMaxTTL: cfg.ServeStaleMaxTTL.Duration,
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
		if cacheConfig.ServeStaleMaxTTL < 0 {
			cacheConfig.ServeStaleMaxTTL = 0
		}
	}

	// Adjust prefetch percentage
	if cacheConfig.Prefetch > 0 && cacheConfig.Prefetch < 10 {
		cacheConfig.Prefetch = 10
	}

	metrics := &CacheMetrics{}

	// RFC 9520 failures no longer occupy the legacy negative answer cache.
	// Give the configured answer-cache budget to the live positive/NXDOMAIN
	// store instead of stranding half of it in an unreachable SERVFAIL cache.
	// Keep one legacy slot so the exported NegativeCache/Store compatibility
	// surface remains non-nil for programmatic users.
	positive := NewPositiveCache(cacheConfig.Size, minTTL, maxTTL, metrics)
	negative := NewNegativeCache(1, minTTL, cacheConfig.NegativeTTL, metrics)
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

	store := NewStore(positive, negative, cacheConfig, failure)
	store.failureCacheDisabled = !cfg.RFC9520Enabled()

	c := &Cache{
		positive: positive,
		negative: negative,
		failure:  failure,
		cfg:      cfg,

		store: store,

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
	// Shared denial state requires validation performed by this resolver.
	// Forwarder AD is a wire assertion, not local provenance, and DNSSEC-off
	// mode cannot safely admit or consume RFC 8020/8198 proofs.
	c.store.sharedDenialDisabled =
		cfg.DNSSEC == "off" || len(cfg.ForwarderServers) != 0
	c.store.rfc8198Disabled = !cfg.RFC8198Enabled()

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
		c.store.FailureLen,
		c.store.NXDomainCutLen,
		c.store.DenialProofLen,
	)

	return c
}

// (*Cache).Name name returns middleware name.
func (c *Cache) Name() string { return name }

// InlineBarrier declares that the cache honors Chain.InlineOnly: an
// inline pass gets the wire ladder and nothing below it — everything
// past the ladder can materialize, wait, or resolve, and a transport
// reader can afford none of those. Its presence is what lets the server
// turn the reader fast path on at all.
func (c *Cache) InlineBarrier() bool { return true }

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

// internalExchange routes CNAME-chase sub-queries through the installed
// Queryer, and hands back the sub-query's own lineage for the caller to
// inherit if it uses the answer.
func (c *Cache) internalExchange(
	ctx context.Context,
	req *dns.Msg,
) (*dns.Msg, subQueryLineage, error) {
	if c.queryer == nil {
		return nil, subQueryLineage{}, errQueryerNotWired
	}

	// The sub-query accumulates its own delegation-cut deadline. Its answer
	// is cached under its own key and must carry its own lineage, not the
	// lifetime of whatever asked for it — a nearly expired alias would
	// otherwise store a freshly resolved target with seconds of life.
	parent := middleware.ResponseMetaFrom(ctx)
	ctx, child := middleware.WithForkedCut(ctx)

	res, err := c.queryer.Query(ctx, req)
	return res, subQueryLineage{parent: parent, child: child}, err
}

// subQueryLineage is a sub-query's delegation-cut bound, held back until the
// caller knows whether it used the answer.
//
// The deriving request inherits the bound because the composed answer
// contains the sub-query's records. A sub-query that contributed none — it
// failed, or returned something the chase did not consume — describes an
// answer nobody is caching, and folding its bound in anyway would shorten an
// outer entry that has not changed.
type subQueryLineage struct {
	parent, child *middleware.ResponseMeta
	inherited     bool
}

// inherit folds the sub-query's bound into the deriving request. Call it
// where the sub-query's records or provenance reach the outer response.
//
// Idempotent: a terminal denial carrying authority records is consumed by
// the generic merge and then again by the branch that adopts its rcode, and
// the second fold would take both metas' locks to learn the same thing.
func (l *subQueryLineage) inherit() {
	if l.child == nil || l.inherited {
		return
	}
	l.inherited = true
	deadline, key := l.child.Cut()
	l.parent.BoundCutFor(deadline, key)
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
// A wire-born request first tries the wire fast path — the exact-entry
// lookup on the wire question through the canonical key, served through
// the writer lease without a decoded request. Everything else — misses,
// composite candidates (NXDOMAIN cut, aggressive denial, failure cache),
// scoped/ECS traffic, prefetch-due entries, Msg-path-only hit shapes —
// falls through to materialization and the ordinary body with every gate
// and lookup it has today.
func (c *Cache) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	// spent carries the rate-limit permit this query already paid on the
	// byte path, if any: the wire path and the Msg body below are the
	// same call, so a plain local is enough to keep one question from
	// costing two tokens. It holds the limiter itself rather than the
	// entry, because a refresh replacing the entry under the same key
	// shares that same limiter — charging the replacement would drop a
	// question that had already paid.
	// The replay pass skips the ladder outright: the inline pass ran it
	// microseconds ago and declined, the Msg body below carries the full
	// capability set the decline fell back for, and a second ladder walk
	// would double the decline diagnostics and the per-entry limiter
	// charge for the same client question.
	var spent *rate.Limiter
	if ch.Request.Undecoded() && !ch.Replay() && c.serveWire(ctx, ch, &spent) {
		return
	}

	// An inline serve runs on a transport reader that must not block.
	// The wire ladder above was its whole budget: everything from here
	// down materializes, may consult the Msg-path cache, and on a miss
	// starts an upstream resolution — none of which a reader can wait
	// out. Decline, unwritten; the transport replays on a worker.
	if ch.InlineOnly() {
		ch.MarkHandoff()
		return
	}

	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	w := ch.Writer

	if len(req.Question) == 0 {
		ch.Cancel()
		return
	}
	q := req.Question[0]
	requestCD := req.CheckingDisabled
	requestHasECS := middleware.HasClientECS(ctx) || hasEDNSClientSubnet(req)
	if requestHasECS {
		// EDNS normally installs this before policy stripping. Preserve the
		// same whole-tree contract for cache-only/custom pipelines where the
		// raw option reaches Cache directly.
		ctx = middleware.MarkClientECS(ctx)
	}
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
	// so SCOPE=0 / pre-Stage-2 entries still hit. Generic and ECS
	// hit metrics are recorded only after handleCacheHit accepts and
	// serves the entry, so retained expired candidates remain misses.
	// ecsLookups breaks ECS
	// requests down by which path served them — operators read it
	// to see how much of the ECS-aware code path is actually
	// carrying traffic (non-ECS lookups are already counted by
	// dns_cache_hits_total / dns_cache_misses_total).
	if clientScope.IsValid() {
		if entry, scopedKey, scope := c.scopedLookup(q, req.CheckingDisabled, clientScope); entry != nil {
			if c.handleCacheHit(ctx, ch, entry, scopedKey, scope, spent) {
				ecsLookupHitScoped.Inc()
				c.metrics.Hit()
				return
			}
		}
	}
	if entry := c.checkCache(cacheKey); entry != nil {
		if c.handleCacheHit(ctx, ch, entry, cacheKey, netip.Prefix{}, spent) {
			if clientScope.IsValid() {
				ecsLookupHitShared.Inc()
			}
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
	// Exact answer and subtree-cut hits need no NSEC3 state. Install the
	// request-tree memo only when aggressive denial lookup is actually
	// reachable, then carry it into resolver fallback and nested subqueries.
	if !requestTreeBypassesSharedDenial &&
		!c.store.sharedDenialDisabled &&
		!c.store.rfc8198Disabled {
		ctx = dnssec.EnsureNSEC3HashMemo(ctx)
	}
	if proof, kind, zone := c.lookupDenialProof(ctx, req, clientScope); proof != nil {
		if c.handleDenialProofHit(ctx, ch, proof, kind, zone) {
			c.metrics.Hit()
			return
		}
	}
	if hit, ok := c.lookupFailure(req, clientScope); ok {
		c.metrics.Hit()
		c.handleFailureHit(ctx, ch, clientScope, hit)
		return
	}
	failureProbe := false
	if retryKey, ok := c.store.FailureRetryKey(req, clientScope); ok {
		dedupKey = retryKey
		failureProbe = true
	}
	// This is the moment the miss witness describes: the denial rung just
	// ran for this question and found nothing. Captured here — not when a
	// failure is eventually recorded, seconds of timeouts later — so a
	// proof admitted during the failing resolution can never be pinned as
	// evidence of its own absence. Nil when the tree bypassed the rung.
	//
	// One accepted residual: the rung and this capture take the read lock
	// separately, so an admission landing in the microseconds between
	// them can be pinned although the rung never saw it. The wire path
	// then keeps serving the RFC 9520 failure where a Msg evaluation
	// would synthesize from the fresh proof — an RFC-legal answer (8198
	// is SHOULD-level), bounded by the failure TTL, in a window the
	// width of two lock acquisitions. Closing it means threading the
	// rung's own candidate set through an exported lookup signature;
	// not worth that surface.
	var denialMissWitness []denialWitnessPair
	if !requestTreeBypassesSharedDenial {
		denialMissWitness = c.store.failureMissWitness(q.Name, q.Qclass)
	}
	c.metrics.Miss()
	if clientScope.IsValid() {
		ecsLookupMiss.Inc()
	}

	// Miss. Dedup upstream work: followers wait for the leader
	// to finish, then re-check the cache — the leader may have
	// just filled it. Ordinary followers that still see a miss
	// proceed to run the upstream chain themselves. Followers of
	// an expired RFC 9520 failure probe re-elect one leader while
	// that failure generation remains: a request-local probe error
	// must not fan every random QNAME out to the authority at once.
	//
	// Followers do NOT call Done: they never registered as a
	// participant. Calling Done from a follower would cancel the
	// leader's context out from under it.
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
	// scope. Read once and reused by the wrapping ResponseWriter:
	// the answer cannot change within one request.
	internal := w.Internal()
	if !internal {
		var (
			previousGeneration   *waitgroup.Generation
			failureProbeRegroups int
		)
		for {
			var (
				generation *waitgroup.Generation
				leader     bool
			)
			if previousGeneration != nil && failureProbe {
				if failureProbeRegroups >= maxFailureProbeRegroups {
					c.writeFailureProbeLimit(ctx, ch)
					return
				}
				generation, leader = c.wg.Regroup(dedupKey, previousGeneration)
				failureProbeRegroups++
			} else {
				generation, leader = c.wg.JoinGeneration(dedupKey)
			}
			if leader {
				leaderKey := dedupKey
				leaderGeneration := generation
				defer c.wg.DoneGeneration(leaderKey, leaderGeneration)
				break
			}

			select {
			case <-generation.Done():
			case <-ctx.Done():
				// Re-election can span several short-lived request-local
				// probe generations. Do not retain a canceled client tree
				// indefinitely while fresh followers keep winning leadership.
				c.stopCanceledRequest(ctx, ch, clientScope)
				return
			}
			// The leader completion and request deadline can become ready in
			// the same scheduler turn. Prefer cancellation deterministically
			// instead of letting select choose the wait branch and regroup.
			if contextutil.EffectiveError(ctx) != nil {
				c.stopCanceledRequest(ctx, ch, clientScope)
				return
			}

			// Re-check both paths after a follower wakes up: the
			// leader may have just stored a scoped entry (a
			// shared-key check would miss it), or a SCOPE=0
			// shared entry (a scoped check alone would miss it).
			if clientScope.IsValid() {
				if entry, scopedKey, scope := c.scopedLookup(q, req.CheckingDisabled, clientScope); entry != nil {
					if c.handleCacheHit(ctx, ch, entry, scopedKey, scope, spent) {
						c.metrics.Hit()
						return
					}
				}
			}
			if entry := c.checkCache(cacheKey); entry != nil {
				if c.handleCacheHit(ctx, ch, entry, cacheKey, netip.Prefix{}, spent) {
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
			if hit, ok := c.lookupFailure(req, clientScope); ok {
				c.metrics.Hit()
				c.handleFailureHit(ctx, ch, clientScope, hit)
				return
			}

			generationTimedOut := errors.Is(generation.Err(), context.DeadlineExceeded)
			if failureProbe && generationTimedOut {
				// The request joined this key specifically as an expired
				// failure probe. Eviction or concurrent recovery may remove
				// the retained failure state while it waits, but an abandoned
				// leader must remain terminal for that cohort or every random
				// QNAME follower would fall through together.
				c.writeFailureProbeLimit(ctx, ch)
				return
			}
			retryKey, retry := c.store.FailureRetryKey(req, clientScope)
			if !retry {
				break
			}
			failureProbe = true
			// A bounded WaitGroup channel may close while its leader remains
			// registered. Never replace a timed-out failure-probe generation
			// or fan its followers through to the authority.
			if generationTimedOut {
				c.writeFailureProbeLimit(ctx, ch)
				return
			}
			previousGeneration = generation
			dedupKey = retryKey
		}
	}

	// Leadership can be won in the same scheduler turn that the ingress
	// query budget expires. Never start downstream resolution for a request
	// whose client tree is already canceled.
	if contextutil.EffectiveError(ctx) != nil {
		c.stopCanceledRequest(ctx, ch, clientScope)
		return
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
	rw.req = ch.Request.Msg()
	rw.requestCD = requestCD
	rw.requestHasECS = requestHasECS
	rw.requestTreeBypassesSharedDenial = requestTreeBypassesSharedDenial
	rw.denialMissWitness = denialMissWitness
	// Stash the client's request scope so WriteMsg can derive
	// the insert key without re-reading the OPT (which by then
	// may have been mutated by the edns wrapper on the response).
	rw.clientScope = clientScope
	rw.meta = meta
	rw.internal = internal
	ch.Writer = rw
	defer func() {
		ch.Writer = w
		rw.ctx = nil
		rw.req = nil
		rw.clientScope = netip.Prefix{}
		rw.requestCD = false
		rw.requestHasECS = false
		rw.requestTreeBypassesSharedDenial = false
		rw.denialMissWitness = nil
		rw.meta = nil
		rw.internal = false
		c.writerPool.Put(rw)
	}()

	ch.Next(ctx)
}

// writeFailureProbeLimit sheds one follower without publishing shared RFC 9520
// state. The exact response marker prevents outer DNS64/failover wrappers from
// interpreting this local SERVFAIL as authority evidence or launching more
// work. Its OPT is rebuilt from scratch so client COOKIE/ECS options are not
// reflected.
func (c *Cache) writeFailureProbeLimit(ctx context.Context, ch *middleware.Chain) {
	c.writeRequestLocalFailure(
		ctx,
		ch,
		middleware.ErrFailureProbeLimit,
		dns.ExtendedErrorCodeOther,
		failureProbeLimitEDEText,
	)
}

func (c *Cache) stopCanceledRequest(
	ctx context.Context,
	ch *middleware.Chain,
	clientScope netip.Prefix,
) {
	err := contextutil.EffectiveError(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		req := ch.Request.Msg()
		if handled, _ := c.writeStaleResponse(
			ctx, ch.Writer, req, req.CheckingDisabled, clientScope, ch.Writer.Internal(),
		); handled {
			ch.Cancel()
			return
		}
		c.writeRequestLocalFailure(
			ctx,
			ch,
			err,
			dns.ExtendedErrorCodeNoReachableAuthority,
			"Query timeout exceeded",
		)
		return
	}
	// A canceled transport generally means the client has gone away; avoid a
	// late write to a closed HTTP/QUIC stream.
	ch.Cancel()
}

func (c *Cache) writeRequestLocalFailure(
	ctx context.Context,
	ch *middleware.Chain,
	err error,
	edeCode uint16,
	edeText string,
) {
	ctx, _ = middleware.EnsureResolutionAttemptGuard(ctx)
	resp := cleanRequestLocalFailureResponse(ch.Request.Msg(), edeCode, edeText)
	middleware.MarkRequestLocalFailureResponse(ctx, resp, err)
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

func cleanRequestLocalFailureResponse(req *dns.Msg, edeCode uint16, edeText string) *dns.Msg {
	resp := new(dns.Msg)
	if req != nil {
		resp.SetReply(req)
	} else {
		resp.Response = true
	}
	resp.Rcode = dns.RcodeServerFailure
	resp.RecursionAvailable = true
	resp.AuthenticatedData = false
	resp.Authoritative = false
	resp.Truncated = false
	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil

	if req == nil {
		return resp
	}
	reqOPT := req.IsEdns0()
	if reqOPT == nil {
		return resp
	}

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(reqOPT.UDPSize())
	opt.SetDo(reqOPT.Do())
	opt.Option = []dns.EDNS0{&dns.EDNS0_EDE{
		InfoCode:  edeCode,
		ExtraText: edeText,
	}}
	resp.Extra = []dns.RR{opt}
	return resp
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

// scopedLookup probes the cache for the most-specific fresh scope that covers
// clientPrefix. When serve-stale retention exposes expired positive entries,
// the first such entry is remembered but does not stop the walk: a wider fresh
// scope must win. If no fresh scoped entry exists, the most-specific expired
// entry is returned so the ordinary hit path can treat it as a miss without
// losing the retained stale candidate. The shared-key fallback remains the
// caller's responsibility.
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
func (c *Cache) scopedLookup(q dns.Question, cd bool, clientPrefix netip.Prefix) (*CacheEntry, uint64, netip.Prefix) {
	if !clientPrefix.IsValid() {
		return nil, 0, netip.Prefix{}
	}
	var (
		expiredEntry *CacheEntry
		expiredKey   uint64
		expiredScope netip.Prefix
	)
	now := time.Now()
	for bits := clientPrefix.Bits(); bits >= 1; bits-- {
		scope, err := clientPrefix.Addr().Prefix(bits)
		if err != nil {
			continue
		}
		key := CacheKey{Question: q, CD: cd, Scope: scope}.Hash()
		entry, ok := c.store.LookupByKey(key)
		if !ok || !entryMatchesKey(entry, CacheKey{Question: q, CD: cd, Scope: scope}) {
			continue
		}
		if entry.remaining(now) > 0 {
			return entry, key, scope
		}
		if expiredEntry == nil {
			expiredEntry, expiredKey, expiredScope = entry, key, scope
		}
	}
	return expiredEntry, expiredKey, expiredScope
}

// lookupNXDomainCut checks the RFC 8020 subtree index after an exact answer
// miss and before RFC 9520 failure state. CD=1 intentionally bypasses local
// synthesis. ECS requests also bypass P4: a signed split-horizon denial can be
// audience-specific, and P4 has no per-scope proof index. Failing open to
// ordinary resolution is safer than sharing one audience's subtree cut.
// lookupFailure is Store.LookupFailure with the forward-zone gate applied to
// the one kind of failure that describes the public namespace.
//
// A zone-kind failure records that an authority zone was unreachable while
// resolving from the root; it says nothing about the upstream a forward zone
// names, and matching by ancestor it would deny the whole forwarded subtree.
// A question-kind failure is the opposite: for a forwarded name it is what the
// forwarder recorded when that zone's own upstream failed, and it is the RFC
// 9520 backoff protecting a dead upstream from being retried by every client
// query. Dropping both would leave that upstream hammered for as long as it
// stayed down.
func (c *Cache) lookupFailure(req *dns.Msg, clientScope netip.Prefix) (FailureHit, bool) {
	hit, ok := c.store.LookupFailure(req, clientScope)
	if !ok || hit.Kind != FailureKindZone {
		return hit, ok
	}
	if req != nil && len(req.Question) > 0 && c.forwardedZoneQuestion(req.Question[0].Name) {
		return FailureHit{}, false
	}
	return hit, ok
}

// forwardedZoneQuestion reports whether qname belongs to a forward zone.
//
// Covering denial and failure state describes the public namespace — it was
// learned by resolving from the root. A forward zone says that subtree is
// answered somewhere else, so an NXDOMAIN cut, aggressive denial or authority
// failure inherited from above it must not answer for it: a name that does
// not exist publicly is precisely what an internal zone is for, and serving
// the public denial would make the zone unreachable for as long as the cut
// lives. Exact entries are deliberately left alone — those were admitted for
// this very question, by whichever path answered it.
func (c *Cache) forwardedZoneQuestion(qname string) bool {
	if c == nil || c.cfg == nil || len(c.cfg.ForwardZones) == 0 {
		return false
	}
	return c.cfg.ForwardZoneFor(qname) != nil
}

func (c *Cache) lookupNXDomainCut(
	ctx context.Context,
	req *dns.Msg,
	clientScope netip.Prefix,
) *nxDomainCutEntry {
	if req == nil || len(req.Question) == 0 ||
		req.CheckingDisabled || clientScope.IsValid() ||
		sharedDenialBypass(ctx) ||
		c.forwardedZoneQuestion(req.Question[0].Name) {
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
		hasEDNSClientSubnet(req) || sharedDenialBypass(ctx) ||
		c.store.rfc8198Disabled ||
		c.forwardedZoneQuestion(req.Question[0].Name) {
		return nil, middleware.ValidatedNegativeProofUnknown, ""
	}
	msg, kind, zone, proofExpires, ok := c.store.lookupDenialProofWithExpiry(
		req,
		newDenialProofWork(ctx, c.dnssecCryptoLimiter),
	)
	if !ok {
		return nil, middleware.ValidatedNegativeProofUnknown, ""
	}
	// The answer exists, so the records behind it were live: bind the request
	// tree to the earliest of their expiries before it is used for anything.
	boundRequestTo(ctx, proofExpires)
	return msg, kind, zone
}

func (c *Cache) handleNXDomainCutHit(
	ctx context.Context,
	ch *middleware.Chain,
	entry *nxDomainCutEntry,
) bool {
	resp := entry.response(ch.Request.Msg())
	if resp == nil {
		return false
	}

	// Same lineage rule as an exact hit: whatever is assembled from this cut
	// inherits its lifetime.
	boundRequestTo(ctx, entry.expires)

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

func (c *Cache) handleFailureHit(
	ctx context.Context,
	ch *middleware.Chain,
	clientScope netip.Prefix,
	hit FailureHit,
) {
	if handled, _ := c.writeStaleResponse(
		ctx, ch.Writer, ch.Request.Msg(), ch.Request.CD(), clientScope, ch.Writer.Internal(),
	); handled {
		ch.Cancel()
		return
	}

	failureCacheHits.Inc()
	resp := hit.Response(ch.Request.Msg())
	if meta := middleware.ResponseMetaFrom(ctx); meta != nil {
		release := meta.MarkCachedFailureResponse(resp)
		defer release()
	}
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

// serveWire is the wire fast path: the exact-entry lookup on the wire
// question through the canonical key, and a verified, wire-eligible hit
// answered through the writer lease without a decoded request. A false
// return is the composite-miss transition point — the caller materializes
// and runs the ordinary body.
func (c *Cache) serveWire(ctx context.Context, ch *middleware.Chain, spent **rate.Limiter) bool {
	req := ch.Request
	if !req.RD() || req.HasECS() {
		return false
	}
	if _, ok := dns.TypeToString[req.Qtype()]; !ok {
		return false
	}
	if _, ok := dns.ClassToString[req.Qclass()]; !ok {
		return false
	}

	key, ok := internalcache.KeyWire(req.WireName(), req.Qtype(), req.Qclass(), req.CD())
	if !ok {
		return false
	}
	// Full-preimage collision verification on the wire: name
	// (case-insensitive), type, class, CD, and the shared/scoped
	// partition. A mismatch is a miss, exactly as at the Msg-path
	// chokepoint. An exact hit that declines materializes — the Msg body
	// re-runs its whole ladder in order, prefetch claims included.
	if entry := c.checkCache(key); entry != nil && entryMatchesWire(entry, req) {
		return c.serveHitFromWire(ctx, ch, entry, spent)
	}
	return c.serveCompositeFromWire(ctx, ch)
}

// serveCompositeFromWire walks the Msg path's composite ladder — RFC 8020
// subtree cut, RFC 8198 aggressive denial, RFC 9520 failure state — in
// its exact order for a wire-born request. Each rung either answers from
// bytes or sends the request to the decoded body, never to a later rung
// it might shadow.
func (c *Cache) serveCompositeFromWire(ctx context.Context, ch *middleware.Chain) bool {
	req := ch.Request
	// Every rung below serves covering state, which a forward zone must not
	// be answered from. Deciding that needs the question in presentation
	// form, so a server with forward zones sends composites to the decoded
	// body and lets the Msg path apply the gate per zone; a server without
	// them pays one length check.
	if c.cfg != nil && len(c.cfg.ForwardZones) > 0 {
		return false
	}
	cd := req.CD()
	if !cd {
		if cut, ok := c.store.LookupNXDomainCutWire(req.WireName(), req.Qclass()); ok {
			return c.serveCutHitFromWire(ctx, ch, cut)
		}
	}
	if hit, ok := c.store.LookupFailureWire(req.WireName(), req.Qtype(), req.Qclass(), cd); ok {
		// The Msg ladder consults RFC 8198 denial before RFC 9520 failure
		// state, and this rung preserves that order without evaluating
		// anything: the failure entry carries a record-time proof that
		// denial missed (the miss witness), and the serve happens only
		// while that proof demonstrably still holds. The proof names one
		// question — witness serving is therefore restricted to
		// question-kind hits, where the lookup and the record coincide in
		// name, type, class and CD; a zone-kind hit answers names the
		// record never proved anything about, so it materializes. Any
		// doubt — a replaced snapshot, a newly cached zone on the path, a
		// pre-witness entry — falls to the Msg path, whose evaluators
		// decide; the client's answer is identical either way. CD skips
		// shared denial on the Msg path too, so it serves directly.
		if cd || ((hit.Kind == FailureKindQuestion || c.store.sharedDenialImpossible()) &&
			c.store.DenialMissHoldsWire(req.WireName(), req.Qclass(), hit)) {
			return c.serveFailureFromWire(ch)
		}
	}
	return false
}

// entryMatchesWire is the wire fast path's collision check: the same
// full-preimage verification the Msg chokepoint runs, with the question
// read from the parsed wire view rather than a decoded message.
func entryMatchesWire(entry *CacheEntry, req *middleware.Request) bool {
	return entryMatchesWireQuestion(entry, req.WireName(), req.Qtype(), req.Qclass(), req.CD())
}

// chargeEntryLimiter pays the per-entry rate-limit token immediately
// before a wire serve commits to answering. A false return means the
// token was refused: the query is cancelled and counted as a hit — the
// Msg path counts a rate-limited hit as a hit, and the byte path must
// answer the same question the same way.
//
// The permit is remembered in spent, keyed by the limiter it was spent
// on: the declines that remain past this point — a lease the writer
// cannot grant, a body that fails to build, a transport fallback — fall
// to the Msg body of the same call, which checks the same limiter again
// and must not charge the same question twice. (A refresh replacing the
// entry under the same key shares the limiter, so the memo survives it.)
// Across the inline/replay boundary no local can carry the permit, which
// is why both serve branches — the flat copy and the chase composition —
// check every decline they can before this charge; what stays past it
// are commit-time backstops, and an inline query dropped there pays a
// second token on the replay, accepted as the rare case.
func (c *Cache) chargeEntryLimiter(ch *middleware.Chain, entry *CacheEntry, spent **rate.Limiter) bool {
	limiter := entry.GetRateLimiter()
	if limiter == nil || *spent == limiter {
		return true
	}
	if !limiter.Allow() {
		c.metrics.Hit()
		ch.Cancel()
		return false
	}
	*spent = limiter
	return true
}

// serveHitFromWire serves one verified exact hit as bytes built in the
// writer's lease. Anything the byte path cannot express declines to the
// ordinary body rather than half-serving.
func (c *Cache) serveHitFromWire(
	ctx context.Context, ch *middleware.Chain, entry *CacheEntry, spent **rate.Limiter,
) bool {
	w := ch.Writer
	if w.Internal() || isStaleAliasChase(ctx) {
		return false
	}
	if entry == nil || entry.remaining(time.Now()) <= 0 {
		return false
	}
	// The deterministic declines run before the limiter spends anything:
	// a prefetch-due entry, an ineligible body, a writer without the
	// lease all fall to the Msg path (or, inline, to the replay), and a
	// token paid here would be paid again there — the exact double
	// charge the spent memo below exists to prevent within one pass, and
	// which no local can prevent across the inline/replay boundary.
	//
	// A prefetch-due hit needs a decoded request copy for the refresh
	// queue; the ordinary body claims it.
	if c.prefetchQueue != nil && entry.PrefetchEligible() && entry.ShouldPrefetch(c.config.Prefetch) {
		return false
	}
	if entry == nil || entry.wireServe&wireEligible == 0 {
		wireSkipEntry.Inc()
		return false
	}
	ww, ok := w.(middleware.WireWriter)
	if !ok {
		wireSkipWriter.Inc()
		return false
	}
	capability, ready := ww.WireReady()
	if !ready {
		wireSkipWriter.Inc()
		return false
	}
	leaser, ok := ww.(middleware.WireBodyLeaser)
	if !ok {
		wireSkipWriter.Inc()
		return false
	}
	if entry.wireServe&wireChaseSafe == 0 {
		// An alias without its terminal: the one exact-entry shape whose
		// reply is composed rather than copied. Fully cache-contained
		// chains serve here; anything else declines to the Msg path,
		// which runs the complete chase machinery. The limiter charge
		// lives inside, past the chase's own decline gates.
		return c.serveChaseHit(ctx, ch, entry, capability, leaser, spent)
	}
	gate := c.effectiveGate(w)
	sc := entry.sidecar.Load()
	if gate != nil && gate.JudgeWireHit(sc) != middleware.WireHitServe {
		wireSkipPolicy.Inc()
		return false
	}
	if mismatch := entry.wireChainMismatch(capability); mismatch != nil {
		mismatch.Inc()
		return false
	}
	stored, _ := entry.wireBodyFor(capability.DO)
	if stored == nil {
		wireSkipDNSSEC.Inc()
		return false
	}
	if !c.chargeEntryLimiter(ch, entry, spent) {
		return true
	}
	dst := leaser.BeginWire(len(stored), capability.Reserve+entry.wireEDEReserve())
	if dst == nil {
		wireSkipWriter.Inc()
		return false
	}
	body, info, built := entry.serveWireIntoRequest(dst, ch.Request, capability.DO)
	if !built {
		leaser.AbortWire()
		wireSkipBuild.Inc()
		return false
	}
	switch err := leaser.CommitWire(body, info); {
	case err == nil:
		if gate != nil {
			gate.CountWireHit(sc)
		}
		boundRequestToEntryLifetime(ctx, entry)
		c.metrics.Hit()
		wireFastServed.Inc()
		ch.Cancel()
		return true
	case errors.Is(err, middleware.ErrWireFallback):
		wireFastFallback.Inc()
		return false
	default:
		// Transport-level failure after commit: the bytes left the
		// process; the response counts as written (Msg-path parity).
		if gate != nil {
			gate.CountWireHit(sc)
		}
		boundRequestToEntryLifetime(ctx, entry)
		c.metrics.Hit()
		ch.Cancel()
		return true
	}
}

// handleCacheHit processes a cache hit. scope is the ECS scope the lookup
// keyed with — zero for the shared key — and is part of what the hit is
// verified against.
func (c *Cache) handleCacheHit(
	ctx context.Context,
	ch *middleware.Chain,
	entry *CacheEntry,
	key uint64,
	scope netip.Prefix,
	spent *rate.Limiter,
) bool {
	w := ch.Writer
	req := ch.Request.Msg()

	// Full-preimage verification (defends against xxhash64 key collisions).
	// The cache key is a non-cryptographic 64-bit hash of the query
	// preimage, so a collision — accidental, or attacker-searched on a
	// chosen qname — would otherwise serve one query's answer to another:
	// across qnames, but equally across the CD partition and the ECS
	// audience, which is why every dimension is compared and not just the
	// question. Returning false treats it as a miss so the chain resolves
	// normally. This is the single chokepoint for every hit (scoped and
	// shared).
	if len(req.Question) == 0 || !entryMatchesKey(entry, CacheKey{
		Question: req.Question[0],
		CD:       req.CheckingDisabled,
		Scope:    scope,
	}) {
		return false
	}
	// Expired entries are misses until a downstream resolution failure makes
	// them eligible for the serve-stale policy. Do this before spending an
	// entry rate-limit token so the later fallback is not charged twice (and
	// cannot be suppressed by a token spent on a response we did not serve).
	if entry.remaining(time.Now()) <= 0 {
		return false
	}
	// A stale alias completion may consume a still-fresh target entry, but
	// RFC 8767 does not allow originally zero-TTL data to become part of the
	// stale response. Force this rare path through the inspected Msg body.
	if isStaleAliasChase(ctx) && entry.hasOriginalZeroTTL() {
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
	// spent is the limiter the byte path already paid a token to on this
	// same query, before declining to here. Compared by limiter and not
	// by entry: a refresh replaces the entry but keeps the limiter, and
	// one question must cost one token however many entry objects it
	// passed through.
	limiter := entry.GetRateLimiter()
	// Asked once and kept: the chase below needs the answer too, and a
	// writer may make more of the question than a field read (a test double
	// treats each call as a rendezvous).
	internal := w.Internal()
	if !internal && limiter != nil && limiter != spent && !limiter.Allow() {
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
				RequestHadECS: middleware.HasClientECS(ctx) ||
					hasEDNSClientSubnet(req),
			}) {
				entry.prefetch.Store(false)
			}
		}
	}

	// The policy verdict is judged once per hit, before the byte/decoded
	// split, because both halves read it: the byte path serves only on
	// WireHitServe, and the decoded fallback restamps on WireHitRestamp.
	// It is judged for internal serves too — the verdict is a pure
	// function of the stored state, and the Msg-path chase reaches its
	// segments through internal sub-queries, which is where a stale
	// segment gets its restamp.
	policyVerdict := middleware.WireHitServe
	policyGate := c.effectiveGate(w)
	var policySC *middleware.Sidecar
	if policyGate != nil {
		policySC = entry.sidecar.Load()
		policyVerdict = policyGate.JudgeWireHit(policySC)
	} else if c.store.sidecarEvaluator != nil && entry.sidecar.Load() == nil {
		// An evaluator without a gate still owes pre-wiring entries
		// their stamp.
		policyVerdict = middleware.WireHitRestamp
	}

	// Byte fast path: serve the stored wire directly. The entry-local gate
	// runs first, then the writer chain's preflight — both allocation-free
	// and together complete, so a request bound for the Msg path never
	// builds a body nor makes the chain compose anything. A hit that never
	// reaches WriteWire records which gate turned it away.
	var served bool
	if skipped := func() *metric.Counter {
		if w.Internal() {
			return wireSkipInternal
		}
		if !entry.wireEligibleFor(req) {
			return wireSkipEntry
		}
		if policyVerdict != middleware.WireHitServe {
			return wireSkipPolicy
		}
		ww, ok := w.(middleware.WireWriter)
		if !ok {
			return wireSkipWriter
		}
		capability, ready := ww.WireReady()
		if !ready {
			return wireSkipWriter
		}
		if mismatch := entry.wireChainMismatch(capability); mismatch != nil {
			return mismatch
		}
		body, info, built := entry.serveWire(req, capability.Reserve, capability.DO)
		if !built {
			return wireSkipBuild
		}
		switch err := ww.WriteWire(body, info); {
		case err == nil:
			if policyGate != nil {
				policyGate.CountWireHit(policySC)
			}
			// The answer is out, so bind the request tree to this entry's
			// lifetime. The byte path is normally reached only by external
			// clients, whose responses nothing derives from — but Queryer is
			// a public interface and SetQueryer does not require a
			// sub-query's writer to report Internal(), so the rule cannot
			// rest on that. Bound only after the write reported success, and
			// never after a fallback: the Msg path below binds once it has a
			// message of its own.
			boundRequestToEntryLifetime(ctx, entry)
			wireFastServed.Inc()
			ch.Cancel()
			served = true
		case errors.Is(err, middleware.ErrWireFallback):
			wireFastFallback.Inc()
			// fall through to the Msg path below
		default:
			// Transport-level failure after commit — mirror the Msg
			// path's ignored WriteMsg error. The body was handed over
			// before the transport was called and the response counts
			// as written, so a caller reading it back through Msg()
			// still gets this entry's answer: it binds like any other
			// terminal outcome. Only a fallback stays unbound, because
			// there the message path binds instead.
			if policyGate != nil {
				policyGate.CountWireHit(policySC)
			}
			boundRequestToEntryLifetime(ctx, entry)
			ch.Cancel()
			served = true
		}
		return nil
	}(); skipped != nil {
		skipped.Inc()
	}
	if served {
		return true
	}

	// Build response from cache
	msg := entry.ToMsg(req)
	if msg == nil {
		// Entry expired between check and use
		return false
	}

	// The decoded serve is where an unusable sidecar gets replaced: the
	// gate judged Restamp — unevaluated, or stamped under a generation it
	// no longer accepts — and this message, TTL-adjusted but
	// record-identical to the stored truth, before the chase below
	// appends other entries' records, is exactly what the admission
	// evaluator would have seen. The CAS is against the judged pointer,
	// stale or nil alike, so the entry rejoins the byte path instead of
	// decoding until eviction; losing the CAS means someone else already
	// restamped the same records.
	if policyVerdict == middleware.WireHitRestamp {
		if ev := c.store.sidecarEvaluator; ev != nil {
			entry.CompareAndStampSidecar(policySC, ev(msg))
		}
	}

	// The message materialized, so the entry was live: bind the request tree
	// to its lifetime before the chase below can derive anything from it.
	boundRequestToEntryLifetime(ctx, entry)

	// Resolve CNAME chains if needed (matching V1 behavior).
	// The depth counter bounds nested chases across the Queryer
	// boundary: each additionalAnswer invocation increments the
	// counter so an inner cache hit on a further CNAME stops
	// chasing once the chain passes maxCnameChaseDepth. Replaces
	// the pre-Phase-3d !w.Internal() guard.
	if depth := cnameChaseDepth(ctx); depth < maxCnameChaseDepth {
		answers, authority, rcode := len(msg.Answer), len(msg.Ns), msg.Rcode
		msg = c.additionalAnswer(withCnameChaseDepth(ctx, depth+1), msg)
		// The chase may have merged records the entry never vouched for: a
		// target resolved fresh by the internal sub-query, whose own write
		// skipped the outgoing checks as every internal write does. Those
		// records reach the client through this write alone, so it applies
		// what WriteMsg applies on a miss: AD withdrawn when a signature
		// has lapsed, and every TTL bounded by the merged records and the
		// request's cut. Without it a hit on an alias served the target at
		// its raw TTL, with AD, and with its lapsed signature.
		if !internal && (len(msg.Answer) != answers || len(msg.Ns) != authority || msg.Rcode != rcode) {
			now := time.Now().UTC()
			mt, _ := dnsutil.ClassifyResponse(msg, now)
			var cut time.Time
			if meta := middleware.ResponseMetaFrom(ctx); meta != nil {
				cut, _ = meta.Cut()
			}
			honestOutgoing(msg, cut, mt, now)
		}
	}

	_ = w.WriteMsg(msg)
	ch.Cancel()
	return true
}

// boundRequestToEntry folds an entry's absolute expiry into the request
// tree's bound, so anything derived from it inherits its lifetime.
//
// The bound is the earlier of the entry's own expiry and the delegation lease
// it inherited — not the lease alone. A cached answer near the end of its TTL
// has the shorter claim, and passing only the lease would let the TTL floor
// re-publish it under whatever is being assembled.
func boundRequestToEntryLifetime(ctx context.Context, entry *CacheEntry) {
	if entry == nil {
		return
	}
	hardUntil := entry.stored.Add(entry.ttl)
	hardKey := uint64(0)
	if !entry.cutUntil.IsZero() && !entry.cutUntil.After(hardUntil) {
		hardUntil, hardKey = entry.cutUntil, entry.cutKey
	}
	if meta := middleware.ResponseMetaFrom(ctx); meta != nil {
		meta.BoundCutFor(hardUntil, hardKey)
	}
}

// boundRequestTo folds an absolute expiry that is already exact — a subtree
// cut's, or the earliest among the records an RFC 8198 answer was synthesized
// from — into the request tree.
func boundRequestTo(ctx context.Context, expires time.Time) {
	if meta := middleware.ResponseMetaFrom(ctx); meta != nil {
		meta.BoundCutFor(expires, 0)
	}
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

// (*Cache).Set adds a new element to the cache. It is retained for source
// compatibility with prefetch and plugin callers. Ordinary answers honor the
// supplied answer-cache key. SERVFAIL uses its full DNS Question instead:
// shared RFC 9520 state verifies the complete key preimage and cannot safely
// accept an opaque hash as its identity.
//
// Internally the entry is constructed with origTTL adjusted to the real
// upstream TTL so subsequent prefetch decisions don't miscalculate from the
// post-Calculate (clamped) value.
func (c *Cache) Set(key uint64, msg *dns.Msg) {
	if len(msg.Question) == 0 {
		return
	}

	filtered := filterCacheableAnswer(msg)
	now := time.Now()
	mt, _ := dnsutil.ClassifyResponse(filtered, now)
	if mt == dnsutil.TypeServerFailure {
		// A compatibility Set runs no ladder, so it can vouch for no miss.
		c.store.RecordFailure(filtered, netip.Prefix{}, FailureProvenance("response"), nil)
		return
	}
	msgTTL := dnsutil.CalculateCacheTTLAt(filtered, mt, now)

	// See Store.setFromResponseWithKey: a denial the zone granted no lifetime
	// is not admitted (RFC 2308 §5), and neither is a signed positive answer
	// whose signature fixes its lifetime at zero.
	ttl := c.positive.ttl.Bound(msgTTL)
	if ttl <= 0 {
		return
	}

	entry := newCacheEntryAt(filtered, ttl, c.config.RateLimit, key, now)
	if entry == nil {
		return
	}
	if ttl > 0 {
		entry.origTTL = uint32(ttl.Seconds())
	}
	c.store.stampSidecar(entry, filtered)

	c.store.SetEntryWithKey(key, entry, mt)
}

// SetSidecarPolicy wires both halves of the sidecar seam
// (middleware.SidecarPolicySetter, injected by Setup before the pipeline
// publishes): the evaluator stamps entries at every admission door, the
// gate judges record-bearing byte serves.
func (c *Cache) SetSidecarPolicy(p middleware.SidecarPolicyProvider) {
	if p == nil {
		return
	}
	c.store.SetSidecarEvaluator(p.SidecarEvaluator())
	c.wireHitGate = p.WireHitGate()
}

// effectiveGate resolves the gate for one hit: the query's own, when the
// policy layer's writer carries one (middleware.QueryPolicyGate — that
// is how held candidates, an already-fallen decision, or an exemption
// reach the byte-serve judgment), else the globally wired gate. Resolved
// once per hit and used for the judge and the count alike, so a
// per-query gate's memoized decision is counted by the same object that
// judged it. Costs one type assertion, and only on the gated path.
func (c *Cache) effectiveGate(w middleware.ResponseWriter) middleware.WireHitGate {
	if c.wireHitGate == nil {
		return nil
	}
	if p, ok := w.(middleware.QueryPolicyGate); ok {
		if g := p.QueryWireHitGate(); g != nil {
			return g
		}
	}
	return c.wireHitGate
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
	// denialMissWitness is the miss witness captured at the denial rung
	// (see denial_proof_witness.go), carried to the failure record a
	// SERVFAIL write-back files. Nil when the tree bypassed the rung.
	denialMissWitness []denialWitnessPair
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
	// internal is the wrapped writer's Internal() flag, read once in
	// ServeDNS. WriteMsg needs it to scope the client-TTL clamp to real
	// client writes, and must not re-query the wrapped writer: the flag
	// cannot change within a request, and one call per request is a
	// contract test doubles rely on.
	internal bool
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
		return w.writeResolutionFailure(ctx, res)
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
	// Re-classified, not merely re-checked. A CNAME that arrived as a success
	// can come back from the chase as a terminal NXDOMAIN or NODATA, and
	// keeping the pre-chase verdict meant the clamp below read the alias TTL
	// while the SOA at the end of the chain said one second. The stores
	// classify for themselves; this is the copy the client gets.
	mt, _ = dnsutil.ClassifyResponse(res, time.Now().UTC())
	if mt == dnsutil.TypeServerFailure {
		return w.writeResolutionFailure(ctx, res)
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
			w.cache.store.SetFromResponseScoped(scopedKey, res, clamped, cutUntil, cutKey)
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
	//
	// A forwarded answer clears only its own question. It proves that zone's
	// upstream is answering; it proves nothing about the public authority
	// chain above the name, which is what the ancestor zone entries record.
	// Clearing those would let one working internal zone wipe the backoff
	// protecting a broken public authority, and the next query for a sibling
	// name would go straight back to hammering it.
	if w.cache.forwardedZoneQuestion(q.Name) {
		w.cache.store.resetQuestionFailure(q, res.CheckingDisabled, w.clientScope)
	} else {
		w.cache.store.resetMatchingFailures(q, res.CheckingDisabled, w.clientScope)
	}

	// The delegation lease caps the TTL the client sees, on this uncached
	// response exactly as remaining() caps it on every later hit. Without
	// this the first response advertised the records' own TTL while hits
	// advertised the lease remainder — two promises for the same records —
	// and, worse than inconsistent, the first client's downstream cache
	// could retain a withdrawn delegation's answer past the parent-granted
	// lease the ghost fix (GHSA-mqfw-f48p-2vc8) bounds everything else to.
	//
	// Last, deliberately: every admission above must see the response as
	// the resolver produced it. The negative-proof provenance fingerprint
	// seals the authority section TTLs included, so clamping before
	// ValidatedNegativeProofForResponse silently disqualified every
	// NXDOMAIN/NODATA proof whose delegation lease ran shorter than its
	// records — the entry stores are unaffected either way, since packing
	// happens inside the Set calls and cutUntil bounds reads regardless.
	//
	// And external writers only: an internal write hands this same message
	// back to a CNAME/DNAME caller that re-verifies the fingerprint before
	// propagating the denial into the outer answer — mutating it here would
	// lose short-lease provenance mid-chain. The outer response inherits
	// the cut through the shared meta and is clamped at the real client
	// write.
	if !w.internal {
		// This resolver has determined the signatures lapsed, so it must not
		// pass on a claim that the data is authenticated (RFC 4035 §3.2.3).
		// A forwarded answer carries whatever AD the upstream asserted, and
		// relaying it here would let a client trust data we know is bogus.
		// The clamp below reduces its TTL to zero; the bit is the other half.
		//
		// Asked as a fact about the records, not read off the classification.
		// Only the NOERROR-with-records shape is ever *named* for an expired
		// signature; a denial whose proof has lapsed is still classified a
		// denial, so an expired NXDOMAIN, an empty NODATA and an alias chain
		// ending in either all kept the bit while their TTLs were correctly
		// clamped to nothing.
		honestOutgoing(res, cutUntil, mt, time.Now().UTC())
	}

	return w.ResponseWriter.WriteMsg(res)
}

func (w *ResponseWriter) writeResolutionFailure(ctx context.Context, res *dns.Msg) error {
	out := res
	if res.Rcode == dns.RcodeServerFailure && middleware.RecursionWorkEnforcementError(ctx) != nil {
		out = w.recursionWorkFailure(res)
	}

	if cacheableResolutionFailure(ctx, out) {
		w.cache.store.RecordFailure(out, w.clientScope, FailureProvenance("response"), w.denialMissWitness)
	}
	if out.Rcode == dns.RcodeServerFailure && staleEligibleResolutionFailure(ctx, out) {
		req := w.req
		if req == nil {
			req = res
		}
		if handled, err := w.cache.writeStaleResponse(
			ctx, w.ResponseWriter, req, w.requestCD, w.clientScope, w.internal,
		); handled {
			return err
		}
	}
	return w.ResponseWriter.WriteMsg(out)
}

// cacheableResolutionFailure admits only failures that describe shared
// resolution state. Work-budget and attempt-limit rejections belong to one
// request tree; optional enrichment, cancellation, and deadline paths likewise
// cannot poison independent clients through the RFC 9520 cache.
func cacheableResolutionFailure(ctx context.Context, res *dns.Msg) bool {
	return contextutil.EffectiveError(ctx) == nil &&
		!middleware.IsBestEffortRecursionWork(ctx) &&
		middleware.RecursionWorkEnforcementError(ctx) == nil &&
		middleware.RequestLocalFailureForResponse(ctx, res) == nil
}

// staleEligibleResolutionFailure is deliberately broader than shared failure
// admission: a request deadline may use an already-retained answer, but it is
// still request-local evidence and must never be published into RFC 9520 state.
// Transport cancellation, optional recursion work, enforcement failures, and
// explicitly marked request-local responses remain ineligible.
func staleEligibleResolutionFailure(ctx context.Context, res *dns.Msg) bool {
	err := contextutil.EffectiveError(ctx)
	return (err == nil || errors.Is(err, context.DeadlineExceeded)) &&
		!errors.Is(err, context.Canceled) &&
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

// honestOutgoing applies, to a message about to leave for an external client,
// the two facts this resolver has established about it: AD is withdrawn when
// an answer or authority RRset has no usable signature left (RFC 4035
// §3.2.3), and every TTL is lowered to the shortest bound the records are
// subject to. The miss path runs it from WriteMsg; the hit path runs it after
// an alias chase merged records the entry never vouched for.
func honestOutgoing(res *dns.Msg, cutUntil time.Time, mt dnsutil.ResponseType, now time.Time) {
	if dnsutil.HasExpiredSignatures(res, now) {
		res.AuthenticatedData = false
	}
	clampTTLsToEffective(res, cutUntil, mt)
}

// clampTTLsToEffective lowers every record TTL in res to the shortest bound
// the answer is subject to: the delegation lease, and the lifetime the records
// and their signatures themselves permit. A past cut clamps to zero — the
// answer is still delivered, but nothing downstream is invited to keep it.
// OPT is hop metadata whose TTL field is not a TTL.
func clampTTLsToEffective(res *dns.Msg, cutUntil time.Time, mt dnsutil.ResponseType) {
	ceiling := time.Duration(-1)
	if !cutUntil.IsZero() {
		ceiling = max(time.Until(cutUntil), 0)
	}

	// Everything the entry will be bounded by, applied to the copy the client
	// is about to receive. Storing the short lifetime and advertising the long
	// one made two different promises about the same records: a signed answer
	// held for a second went out with the hour its records claimed, and a
	// denial the SOA granted one second went out with three hundred. The first
	// client's own cache then outlived the ceiling by the whole difference.
	//
	// Only downward. The derivation applies the positive floor, which is about
	// how long this cache re-asks, and is no business of the client's.
	// Every record being handed over, not the narrower set the entry keeps.
	// The stored view drops the CNAME target's own RRset, which belongs to a
	// different owner, and that RRset is in this message and is what the
	// client will act on: a target expiring in two seconds went out under an
	// alias advertising five minutes.
	//
	// Zero is folded in like any other value. It is a real ceiling, an SOA
	// granting no lifetime or a signature whose Original TTL is zero, and
	// treating it as "nothing found" left the first client holding, at its
	// full advertised TTL, data this cache had just refused to admit.
	derived := dnsutil.CalculateCacheTTL(res, mt)
	leaseBinding := ceiling >= 0 && derived >= ceiling
	if ceiling < 0 || derived < ceiling {
		ceiling = derived
	}
	if ceiling < 0 {
		return
	}

	// The same rounding a cache hit gets. The two paths answer the same
	// question about the same records and disagreeing on the last fraction of
	// a second is how one client is told nothing and the next is told one.
	// And the same exception: a sub-second delegation lease is not rounded
	// up into a second the parent never granted; the answer goes out with
	// nothing to keep, exactly as a hit in that state does (servedTTL).
	secs := servedSeconds(ceiling)
	if leaseBinding && ceiling < time.Second {
		secs = 0
	}
	clamp := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > secs {
				rr.Header().Ttl = secs
			}
		}
	}
	clamp(res.Answer)
	clamp(res.Ns)
	clamp(res.Extra)
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

	keep := func(r dns.RR) bool {
		// As DNS names: a text fold kept a record whose owner is
		// wire-distinct from the question but folds to it in Unicode.
		if r.Header().Rrtype == dns.TypeDNAME ||
			dnsname.CanonicalCompare(res.Question[0].Name, r.Header().Name) == 0 {
			return true
		}
		rrsig, ok := r.(*dns.RRSIG)
		return ok && rrsig.TypeCovered == dns.TypeDNAME
	}

	// Every consumer reads the result synchronously and retains bytes, not
	// records — NewCacheEntryWithKey builds its own shallow storable view,
	// PackClones it on the spot, and value-copies the one option it keeps
	// (the EDE) — so a deep copy duplicated every RR in every section for
	// a reader that only wants a different Answer slice. The common shape,
	// no chain tail to drop, passes through untouched.
	drop := false
	for _, r := range res.Answer {
		if !keep(r) {
			drop = true
			break
		}
	}
	if !drop {
		return res
	}

	answer := make([]dns.RR, 0, len(res.Answer))
	for _, r := range res.Answer {
		if keep(r) {
			answer = append(answer, r)
		}
	}

	filtered := *res
	filtered.Answer = answer
	return &filtered
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

		respCname, lineage, err := c.internalExchange(ctx, cnameReq)
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
			// The sub-query's records are now part of the outer answer, so
			// the outer answer inherits how long they may be served.
			lineage.inherit()
		}

		if respCname != nil && respCname.Rcode == dns.RcodeNameError {
			// The internal query has already reached the terminal denied
			// name. Do not query a target below that cut again, and retain
			// the exact locally validated proof provenance rather than
			// attributing the NXDOMAIN to the outer alias owner.
			msg.Rcode = dns.RcodeNameError
			middleware.PropagateValidatedDenialResponse(ctx, respCname, msg)
			// The outer response is now this denial, proof and all.
			lineage.inherit()
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
				// The outer response now carries the target's terminal proof.
				lineage.inherit()
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
