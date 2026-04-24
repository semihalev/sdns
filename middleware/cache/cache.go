package cache

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/sdns/waitgroup"
	"github.com/semihalev/zlog/v2"
)

var debugns bool

func init() {
	_, debugns = os.LookupEnv("SDNS_DEBUGNS")
}

const (
	name   = "cache"
	maxTTL = util.MaxCacheTTL
	minTTL = util.MinCacheTTL
)

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

	config  CacheConfig
	metrics *CacheMetrics

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

		config:  cacheConfig,
		metrics: metrics,

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

// (*Cache).Store returns the storage facade. Exposed for future
// wiring (queryer, resolver sub-queries, api purge) that needs to
// read or write cache entries without going through ServeDNS.
func (c *Cache) Store() *Store { return c.store }

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

	// Cache key uses (name, qtype, class, CD) — same granularity
	// as the dedup key so followers release into a lookup that
	// matches what the leader wrote.
	cacheKey := CacheKey{Question: q, CD: req.CheckingDisabled}.Hash()

	// Hot path: cache check before dedup. Concurrent cache hits
	// used to take the waitgroup lock and allocate a Join
	// context/timer even when the entry was already live.
	if entry := c.checkCache(cacheKey); entry != nil {
		if w.Internal() && entry.prefetch.Load() {
			// Prefetch path: fall through to the resolver.
		} else if c.handleCacheHit(ctx, ch, entry, cacheKey) {
			return
		}
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
	if !w.Internal() {
		if wait := c.wg.Join(cacheKey); wait != nil {
			<-wait
			if entry := c.checkCache(cacheKey); entry != nil {
				if c.handleCacheHit(ctx, ch, entry, cacheKey) {
					return
				}
			}
		} else {
			defer c.wg.Done(cacheKey)
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
	ch.Writer = rw
	defer func() {
		ch.Writer = w
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

// handleCacheHit processes a cache hit.
func (c *Cache) handleCacheHit(ctx context.Context, ch *middleware.Chain, entry *CacheEntry, key uint64) bool {
	w := ch.Writer
	req := ch.Request

	// Check rate limiting
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
	if c.prefetchQueue != nil && entry.ShouldPrefetch(c.config.Prefetch) {
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

	// Resolve CNAME chains if needed (matching V1 behavior)
	if !w.Internal() {
		msg = c.additionalAnswer(ctx, msg)
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
func (c *Cache) handleSpecialQuery(ctx context.Context, ch *middleware.Chain, q dns.Question) bool {
	// Handle cache purge
	if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL {
		if qname, qtype, ok := util.ParsePurgeQuestion(ch.Request); ok {
			c.purge(qname, qtype)
			ch.Next(ctx)
			return true
		}
	}

	// Handle debug queries
	if debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO {
		ch.Next(ctx)
		return true
	}

	return false
}

// purge removes entries from cache.
func (c *Cache) purge(qname string, qtype uint16) {
	c.store.Purge(dns.Question{Name: qname, Qtype: qtype, Qclass: dns.ClassINET})
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
	mt, _ := util.ClassifyResponse(filtered, time.Now().UTC())
	msgTTL := util.CalculateCacheTTL(filtered, mt)

	var ttl time.Duration
	if mt == util.TypeServerFailure {
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
	key := CacheKey{Question: q, CD: res.CheckingDisabled}.Hash()
	w.cache.store.SetFromResponseWithKey(key, res)

	// Resolve CNAME chains before sending to client (matching V1 behavior)
	if !w.Internal() {
		res = w.cache.additionalAnswer(context.Background(), res)
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

	cnameReq.SetEdns0(util.DefaultMsgSize, true)
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
				return util.SetRcode(msg, dns.RcodeServerFailure, false)
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
		for _, t := range targets {
			if t == target {
				return util.SetRcode(msg, dns.RcodeServerFailure, false)
			}
		}

		targets = append(targets, target)

		respCname, err := util.ExchangeInternal(ctx, cnameReq)
		if err == nil && (len(respCname.Answer) > 0 || len(respCname.Ns) > 0) {
			target, child = searchAdditionalAnswer(msg, respCname)
		}

		if target == q.Name {
			return util.SetRcode(msg, dns.RcodeServerFailure, false)
		}

		cnameReq.Question[0].Name = target

		cnameDepth--

		if child && cnameDepth > 0 {
			goto lookup
		}

		if respCname != nil && respCname.Rcode == dns.RcodeNameError {
			msg.Rcode = dns.RcodeNameError
		}
	}

	return msg
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
