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

// Cache is the cache implementation.
type Cache struct {
	positive *PositiveCache
	negative *NegativeCache

	// store is the public-facing storage facade backed by the same
	// positive/negative sub-caches. External callers (resolver
	// sub-queries, queryer-driven prefetch, future API purge wiring)
	// route through Store; the middleware itself uses both views —
	// Store for the new API surface, direct sub-cache access for
	// the few existing hot paths that already have a key in hand.
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

	c := &Cache{
		positive: positive,
		negative: negative,

		store: NewStore(positive, negative, cacheConfig),

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
	SetCacheSizeFuncs(c.positive.Len, c.negative.Len)

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
	// records the metric on the shared-key path; scopedLookup
	// records its own Hit on the scoped path so we don't
	// double-count or under-count. ecsLookups breaks the same
	// outcome down by ECS-vs-shared so operators can see how much
	// the scoped path is actually carrying.
	if clientScope.IsValid() {
		if entry, scopedKey := c.scopedLookup(q, req.CheckingDisabled, clientScope); entry != nil {
			ecsLookups.WithLabelValues("hit_scoped").Inc()
			if c.handleCacheHit(ctx, ch, entry, scopedKey) {
				return
			}
		}
	}
	if entry := c.checkCache(cacheKey); entry != nil {
		if clientScope.IsValid() {
			ecsLookups.WithLabelValues("hit_shared").Inc()
		} else {
			ecsLookups.WithLabelValues("non_ecs").Inc()
		}
		if c.handleCacheHit(ctx, ch, entry, cacheKey) {
			return
		}
	} else if clientScope.IsValid() {
		ecsLookups.WithLabelValues("miss").Inc()
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
						return
					}
				}
			}
			if entry := c.checkCache(cacheKey); entry != nil {
				if c.handleCacheHit(ctx, ch, entry, cacheKey) {
					return
				}
			}
		} else {
			defer c.wg.Done(dedupKey)
		}
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
	// Stash the client's request scope so WriteMsg can derive
	// the insert key without re-reading the OPT (which by then
	// may have been mutated by the edns wrapper on the response).
	rw.clientScope = clientScope
	ch.Writer = rw
	defer func() {
		ch.Writer = w
		rw.ctx = nil
		rw.clientScope = netip.Prefix{}
		c.writerPool.Put(rw)
	}()

	ch.Next(ctx)
}

// checkCache checks both positive and negative caches and records
// a single Hit/Miss metric per call. Sub-cache Get no longer
// records its own metrics, so a miss in the positive cache that
// then hits the negative cache (or vice versa) counts once.
func (c *Cache) checkCache(key uint64) *CacheEntry {
	if entry, ok := c.store.LookupByKey(key); ok {
		c.metrics.Hit()
		return entry
	}

	c.metrics.Miss()
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

// scopedLookup probes the cache for the longest scope match that
// covers `clientPrefix`. Returns the entry + the key it was found
// under, or (nil, 0) on miss. The shared-key fallback is the
// caller's responsibility — a scoped probe that misses should still
// try the unscoped key in case the authority returned SCOPE=0
// (cached shared) or the entry predates Stage 2.
//
// Iteration runs from the client's source prefix down to the
// policy's min_scope ceiling, clamped to never exceed the client
// prefix itself: when a client sends a source broader than
// min_scope (e.g. /20 with min_scope_v4=24) Policy.Clamp passes
// the /20 through unchanged and ClampScope stores answers at /20,
// so the lookup must also reach /20 or the inserted entry can
// never be hit again. Probing wider than the client prefix
// would walk past what the client itself sent — that range would
// never match an entry derived from this client's source.
//
// Worst case is ~9 probes for IPv4 (forward_v4 down to min_scope_v4)
// and ~9 for IPv6 (forward_v6 down to min_scope_v6); each probe is
// one hash compute + one map lookup, well below the cost of an
// upstream resolution.
func (c *Cache) scopedLookup(q dns.Question, cd bool, clientPrefix netip.Prefix) (*CacheEntry, uint64) {
	if !clientPrefix.IsValid() {
		return nil, 0
	}
	var minBits int
	if clientPrefix.Addr().Is4() {
		minBits = int(c.ecsPolicy.MinScopeV4)
	} else {
		minBits = int(c.ecsPolicy.MinScopeV6)
	}
	// Clamp the lower bound to never exceed the client's own prefix —
	// otherwise a broader-than-min client (/20 with min_scope_v4=24)
	// would do zero probes even though insert can store at /20.
	if clientPrefix.Bits() < minBits {
		minBits = clientPrefix.Bits()
	}
	for bits := clientPrefix.Bits(); bits >= minBits; bits-- {
		scope, err := clientPrefix.Addr().Prefix(bits)
		if err != nil {
			continue
		}
		key := CacheKey{Question: q, CD: cd, Scope: scope}.Hash()
		if entry, ok := c.store.LookupByKey(key); ok {
			c.metrics.Hit()
			return entry, key
		}
	}
	return nil, 0
}

// handleCacheHit processes a cache hit.
func (c *Cache) handleCacheHit(ctx context.Context, ch *middleware.Chain, entry *CacheEntry, key uint64) bool {
	w := ch.Writer
	req := ch.Request

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
	msgTTL := dnsutil.CalculateCacheTTL(filtered, mt)

	var ttl time.Duration
	if mt == dnsutil.TypeServerFailure {
		ttl = c.negative.ttl.Calculate(msgTTL)
	} else {
		ttl = c.positive.ttl.Calculate(msgTTL)
	}

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
		"hits":          hits,
		"misses":        misses,
		"evictions":     evictions,
		"prefetches":    prefetches,
		"positive_size": c.store.PositiveLen(),
		"negative_size": c.store.NegativeLen(),
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
	// clientScope is the prefix derived from the request's ECS
	// option (already clamped by the edns middleware to the policy
	// ceiling). Zero value when ECS doesn't apply, in which case
	// WriteMsg falls back to the unscoped insert path bit-for-bit
	// — that's how pre-Stage-2 traffic and SCOPE=0 responses keep
	// the same cache shape they had before.
	clientScope netip.Prefix
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
	if w.clientScope.IsValid() {
		if respScope, ok := ecs.ReadResponseScope(res); ok {
			clamped := w.cache.ecsPolicy.ClampScope(respScope, w.clientScope)
			scopedKey := CacheKey{Question: q, CD: res.CheckingDisabled, Scope: clamped}.Hash()
			w.cache.store.SetFromResponseScoped(scopedKey, res)
		} else {
			// No SCOPE in response (or SCOPE=0): authority says
			// "global"; cache shared so future non-ECS clients hit.
			key := CacheKey{Question: q, CD: res.CheckingDisabled}.Hash()
			w.cache.store.SetFromResponseWithKey(key, res)
		}
	} else {
		key := CacheKey{Question: q, CD: res.CheckingDisabled}.Hash()
		w.cache.store.SetFromResponseWithKey(key, res)
	}

	// Resolve CNAME chains before sending to client (matching V1
	// behavior). Depth counter replaces the pre-Phase-3d
	// !w.Internal() guard; the active request ctx was stashed on
	// this writer by Cache.ServeDNS so WriteMsg can read it
	// without the caller plumbing ctx through the
	// dns.ResponseWriter interface.
	ctx := w.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if depth := cnameChaseDepth(ctx); depth < maxCnameChaseDepth {
		res = w.cache.additionalAnswer(withCnameChaseDepth(ctx, depth+1), res)
	}

	return w.ResponseWriter.WriteMsg(res)
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
		if err == nil && (len(respCname.Answer) > 0 || len(respCname.Ns) > 0) {
			target, child = searchAdditionalAnswer(msg, respCname)
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

		if respCname != nil && respCname.Rcode == dns.RcodeNameError {
			msg.Rcode = dns.RcodeNameError
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
