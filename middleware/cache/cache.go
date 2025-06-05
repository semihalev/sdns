package cache

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/sdns/waitgroup"
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

// Cache is the cache implementation
type Cache struct {
	positive *PositiveCache
	negative *NegativeCache

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

// New creates a new cache
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

	// Validate configuration
	if err := cacheConfig.Validate(); err != nil {
		// Log error but continue with defaults
		log.Warn("Cache configuration validation failed, using defaults", "error", err.Error())
	}

	// Adjust prefetch percentage
	if cacheConfig.Prefetch > 0 && cacheConfig.Prefetch < 10 {
		cacheConfig.Prefetch = 10
	}

	metrics := &CacheMetrics{}

	c := &Cache{
		positive: NewPositiveCache(cacheConfig.Size/2, minTTL, maxTTL, metrics),
		negative: NewNegativeCache(cacheConfig.Size/2, minTTL, cacheConfig.NegativeTTL, metrics),

		config:  cacheConfig,
		metrics: metrics,

		wg: waitgroup.New(15 * time.Second),

		writerPool: sync.Pool{
			New: func() interface{} {
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

	return c
}

// Name returns middleware name
func (c *Cache) Name() string { return name }

// ServeDNS implements the middleware.Handler interface
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

	// Generate deduplication key (matches V1 behavior: uses TypeNULL)
	dedupKey := CacheKey{Question: dns.Question{Name: q.Name, Qtype: dns.TypeNULL, Qclass: dns.ClassINET}, CD: false}.Hash()

	// Deduplicate concurrent requests for the same query name
	if !w.Internal() {
		c.wg.Wait(dedupKey)
	}

	// Generate cache lookup key with actual question type and CD flag
	cacheKey := CacheKey{Question: q, CD: req.CheckingDisabled}.Hash()

	// Check cache
	if entry := c.checkCache(cacheKey); entry != nil {
		// Skip cache for internal prefetch queries (like old implementation)
		if w.Internal() && entry.prefetch.Load() {
			// This is a prefetch query, skip cache and go to resolver
		} else if c.handleCacheHit(ctx, ch, entry, cacheKey) {
			return
		}
	}

	// Cache miss - proceed with resolution
	if !w.Internal() {
		c.wg.Add(dedupKey)
		defer c.wg.Done(dedupKey)
	}

	// Use pooled response writer
	rw := c.writerPool.Get().(*ResponseWriter)
	rw.ResponseWriter = w
	rw.cache = c
	ch.Writer = rw

	ch.Next(ctx)

	// Return writer to pool
	ch.Writer = w
	c.writerPool.Put(rw)
}

// checkCache checks both positive and negative caches
func (c *Cache) checkCache(key uint64) *CacheEntry {
	// Check positive cache first
	if entry, ok := c.positive.Get(key); ok {
		return entry
	}

	// Check negative cache
	if entry, ok := c.negative.Get(key); ok {
		return entry
	}

	return nil
}

// handleCacheHit processes a cache hit
func (c *Cache) handleCacheHit(ctx context.Context, ch *middleware.Chain, entry *CacheEntry, key uint64) bool {
	w := ch.Writer
	req := ch.Request

	// Check rate limiting
	if !w.Internal() && entry.limiter != nil && !entry.limiter.Allow() {
		ch.Cancel()
		return true
	}

	// Check if prefetch is needed
	if c.prefetchQueue != nil && entry.ShouldPrefetch(c.config.Prefetch) {
		if entry.prefetch.CompareAndSwap(false, true) {
			c.prefetchQueue.Add(PrefetchRequest{
				Request: req.Copy(),
				Key:     key,
				Cache:   c,
			})
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

// isValidQuery checks if the query is valid
func (c *Cache) isValidQuery(q dns.Question) bool {
	if v := dns.ClassToString[q.Qclass]; v == "" {
		return false
	}
	if v := dns.TypeToString[q.Qtype]; v == "" {
		return false
	}
	return true
}

// handleSpecialQuery handles CHAOS and other special queries
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

// purge removes entries from cache
func (c *Cache) purge(qname string, qtype uint16) {
	q := dns.Question{Name: qname, Qtype: qtype, Qclass: dns.ClassINET}

	// Purge both CD and non-CD versions
	for _, cd := range []bool{false, true} {
		key := CacheKey{Question: q, CD: cd}.Hash()
		c.positive.Remove(key)
		c.negative.Remove(key)
	}
}

// Stop gracefully shuts down the cache
func (c *Cache) Stop() {
	if c.prefetchQueue != nil {
		c.prefetchQueue.Stop()
	}
}

// Set adds a new element to the cache. Provided for API compatibility.
func (c *Cache) Set(key uint64, msg *dns.Msg) {
	if len(msg.Question) == 0 {
		return
	}

	// Filter the message like ResponseWriter does
	rw := &ResponseWriter{cache: c}
	filtered := rw.filterAnswerSection(msg)

	mt, _ := util.ClassifyResponse(filtered, time.Now().UTC())

	msgTTL := util.CalculateCacheTTL(filtered, mt)
	var ttl time.Duration
	if mt == util.TypeServerFailure {
		ttl = c.negative.ttl.Calculate(msgTTL)
	} else {
		ttl = c.positive.ttl.Calculate(msgTTL)
	}

	// Create entry with proper original TTL for prefetch calculation
	entry := NewCacheEntry(filtered, ttl, c.config.RateLimit)
	// Ensure origTTL reflects the actual TTL from the response for prefetch calculations
	if ttl > 0 {
		entry.origTTL = uint32(ttl.Seconds())
	}

	switch mt {
	case util.TypeSuccess, util.TypeReferral:
		c.positive.Set(key, entry)
	case util.TypeNXDomain, util.TypeNoRecords:
		// NXDOMAIN and NODATA go to positive cache with normal TTL handling
		c.positive.Set(key, entry)
	case util.TypeServerFailure:
		// Server failures and other errors go to negative cache with expire limit
		c.negative.Set(key, entry)
	}
}

// Stats returns cache statistics
func (c *Cache) Stats() map[string]interface{} {
	hits, misses, evictions, prefetches := c.metrics.Stats()

	return map[string]interface{}{
		"hits":          hits,
		"misses":        misses,
		"evictions":     evictions,
		"prefetches":    prefetches,
		"positive_size": c.positive.Len(),
		"negative_size": c.negative.Len(),
		"hit_rate": func() float64 {
			total := float64(hits + misses)
			if total == 0 {
				return 0
			}
			return float64(hits) / total * 100
		}(),
	}
}

// ResponseWriter is the response writer for cache
type ResponseWriter struct {
	middleware.ResponseWriter
	cache *Cache
}

// WriteMsg implements the ResponseWriter interface
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

	// Determine cache type and TTL
	mt, _ := util.ClassifyResponse(res, time.Now().UTC())
	key := CacheKey{Question: q, CD: res.CheckingDisabled}.Hash()

	// Filter answer section to only keep relevant records (matching V1 behavior)
	filtered := w.filterAnswerSection(res)

	// Calculate TTL
	msgTTL := util.CalculateCacheTTL(filtered, mt)
	var ttl time.Duration

	switch mt {
	case util.TypeSuccess, util.TypeReferral:
		ttl = w.cache.positive.ttl.Calculate(msgTTL)
		entry := NewCacheEntry(filtered, ttl, w.cache.config.RateLimit)
		w.cache.positive.Set(key, entry)

	case util.TypeNXDomain, util.TypeNoRecords:
		ttl = w.cache.positive.ttl.Calculate(msgTTL)
		entry := NewCacheEntry(filtered, ttl, w.cache.config.RateLimit)
		w.cache.positive.Set(key, entry)

	case util.TypeServerFailure:
		ttl = w.cache.negative.ttl.Calculate(msgTTL)
		entry := NewCacheEntry(filtered, ttl, w.cache.config.RateLimit)
		w.cache.negative.Set(key, entry)
	}

	// Resolve CNAME chains before sending to client (matching V1 behavior)
	if !w.Internal() {
		res = w.cache.additionalAnswer(context.Background(), res)
	}

	return w.ResponseWriter.WriteMsg(res)
}

// filterAnswerSection filters the answer section to only keep relevant records
// This matches the V1 behavior of only caching records that are directly relevant
func (w *ResponseWriter) filterAnswerSection(res *dns.Msg) *dns.Msg {
	if len(res.Answer) == 0 {
		return res
	}

	// Create a copy to avoid modifying the original
	filtered := res.Copy()
	var answer []dns.RR

	for _, r := range filtered.Answer {
		// Keep DNAME records or records matching the query name
		if r.Header().Rrtype == dns.TypeDNAME ||
			strings.EqualFold(res.Question[0].Name, r.Header().Name) {
			answer = append(answer, r)
		}

		// Keep RRSIG records for DNAME that don't match the query name
		if rrsig, ok := r.(*dns.RRSIG); ok {
			if rrsig.TypeCovered == dns.TypeDNAME &&
				!strings.EqualFold(res.Question[0].Name, r.Header().Name) {
				answer = append(answer, r)
			}
		}
	}

	filtered.Answer = answer
	return filtered
}

// messagePool reduces allocations by reusing dns.Msg structs
var messagePool = sync.Pool{
	New: func() interface{} {
		return &dns.Msg{
			// Pre-allocate slices with typical sizes to avoid allocations
			Question: make([]dns.Question, 0, 1), // Most queries have 1 question
			Answer:   make([]dns.RR, 0, 10),      // Pre-allocate for typical responses
			Ns:       make([]dns.RR, 0, 5),       // Authority section
			Extra:    make([]dns.RR, 0, 2),       // Additional section (often OPT record)
		}
	},
}

// AcquireMsg returns an empty msg from pool with pre-allocated slices
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

// ReleaseMsg returns msg to pool
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

// additionalAnswer implements the v1 CNAME resolution logic
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

// searchAdditionalAnswer merges the CNAME response into the original message
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
