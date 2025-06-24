package cache

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"golang.org/x/time/rate"
)

// DNSCache defines the interface for DNS cache implementations.
type DNSCache interface {
	Get(key uint64) (*CacheEntry, bool)
	Set(key uint64, entry *CacheEntry)
	Remove(key uint64)
	Len() int
}

// CacheEntry represents an immutable cache entry.
type CacheEntry struct {
	wire     []byte // Pre-packed DNS message in wire format
	stored   int64  // Unix timestamp (more memory efficient)
	ttl      uint32 // TTL in seconds
	origTTL  uint32 // Original TTL in seconds for prefetch calculation
	prefetch atomic.Bool
	rateKey  int    // Key for shared rate limiter lookup (0 = no limit)
	hasEDE   bool   // Whether EDE is present
	edeCode  uint16 // EDE code if present
	edeText  string // EDE extra text (empty if no text)
}

// rateLimiterEntry holds a rate limiter with last access time
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// rateLimiterCache provides shared rate limiters to avoid creating one per entry
var rateLimiterCache = struct {
	sync.RWMutex
	limiters    map[int]*rateLimiterEntry
	maxSize     int
	cleanupTime time.Duration
}{
	limiters:    make(map[int]*rateLimiterEntry),
	maxSize:     1000,             // Maximum number of different rate limiters to cache
	cleanupTime: 30 * time.Minute, // Remove limiters not accessed for 30 minutes
}

func init() {
	// Start periodic cleanup goroutine
	go rateLimiterCacheMaintenance()
}

// rateLimiterCacheMaintenance periodically cleans up old rate limiters
func rateLimiterCacheMaintenance() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cleanupRateLimiters()
	}
}

// cleanupRateLimiters removes expired rate limiters
func cleanupRateLimiters() {
	rateLimiterCache.Lock()
	defer rateLimiterCache.Unlock()

	now := time.Now()
	for key, entry := range rateLimiterCache.limiters {
		if now.Sub(entry.lastAccess) > rateLimiterCache.cleanupTime {
			delete(rateLimiterCache.limiters, key)
		}
	}

	// If still too many, remove oldest entries
	if len(rateLimiterCache.limiters) > rateLimiterCache.maxSize {
		// Convert to slice for sorting
		type kv struct {
			key   int
			entry *rateLimiterEntry
		}
		items := make([]kv, 0, len(rateLimiterCache.limiters))
		for k, v := range rateLimiterCache.limiters {
			items = append(items, kv{k, v})
		}

		// Sort by last access time (oldest first)
		sort.Slice(items, func(i, j int) bool {
			return items[i].entry.lastAccess.Before(items[j].entry.lastAccess)
		})

		// Remove oldest entries
		toRemove := len(items) - rateLimiterCache.maxSize
		for i := 0; i < toRemove; i++ {
			delete(rateLimiterCache.limiters, items[i].key)
		}
	}
}

func getSharedRateLimiter(rateLimit int) *rate.Limiter {
	if rateLimit <= 0 {
		return nil
	}

	now := time.Now()

	// Try to get existing limiter
	rateLimiterCache.RLock()
	entry, exists := rateLimiterCache.limiters[rateLimit]
	rateLimiterCache.RUnlock()

	if exists {
		// Update last access time
		rateLimiterCache.Lock()
		entry.lastAccess = now
		rateLimiterCache.Unlock()
		return entry.limiter
	}

	// Create new limiter
	rateLimiterCache.Lock()
	defer rateLimiterCache.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := rateLimiterCache.limiters[rateLimit]; exists {
		entry.lastAccess = now
		return entry.limiter
	}

	// Create new shared limiter
	limit := rate.Every(time.Second / time.Duration(rateLimit))
	limiter := rate.NewLimiter(limit, rateLimit)

	rateLimiterCache.limiters[rateLimit] = &rateLimiterEntry{
		limiter:    limiter,
		lastAccess: now,
	}

	return limiter
}

// NewCacheEntry creates a new cache entry from a DNS message.
func NewCacheEntry(msg *dns.Msg, ttl time.Duration, rateLimit int) *CacheEntry {
	// Create a filtered copy to remove OPT records but preserve structure
	msgCopy := new(dns.Msg)
	msgCopy.MsgHdr = msg.MsgHdr
	msgCopy.Compress = msg.Compress
	msgCopy.Question = msg.Question
	msgCopy.Answer = msg.Answer
	msgCopy.Ns = msg.Ns

	var edeCode uint16
	var edeText string
	var hasEDE bool

	// Filter Extra section to remove OPT records but preserve EDE
	if len(msg.Extra) > 0 {
		extra := make([]dns.RR, 0, len(msg.Extra))
		for _, rr := range msg.Extra {
			if opt, ok := rr.(*dns.OPT); ok {
				// Extract EDE if present
				for _, option := range opt.Option {
					if e, ok := option.(*dns.EDNS0_EDE); ok {
						edeCode = e.InfoCode
						edeText = e.ExtraText
						hasEDE = true
						break
					}
				}
			} else {
				extra = append(extra, rr)
			}
		}
		msgCopy.Extra = extra
	}

	// Pack the filtered message into wire format
	wire, err := msgCopy.Pack()
	if err != nil {
		// If packing fails, return nil to avoid caching invalid data
		// This can happen with malformed DNS messages or messages that exceed size limits
		// The caller should handle nil returns gracefully
		return nil
	}

	entry := &CacheEntry{
		wire:    wire,
		stored:  time.Now().Unix(),
		ttl:     uint32(ttl.Seconds()),
		origTTL: uint32(ttl.Seconds()),
		rateKey: rateLimit,
		hasEDE:  hasEDE,
		edeCode: edeCode,
		edeText: edeText,
	}

	return entry
}

// (*CacheEntry).ToMsg toMsg creates a response message with updated TTLs.
func (e *CacheEntry) ToMsg(req *dns.Msg) *dns.Msg {
	now := time.Now().Unix()
	elapsed := now - e.stored
	remainingTTL := int64(e.ttl) - elapsed

	if remainingTTL <= 0 {
		return nil
	}

	// Unpack the wire format
	resp := new(dns.Msg)
	if err := resp.Unpack(e.wire); err != nil {
		return nil
	}

	// Save original values before SetReply
	originalRcode := resp.Rcode
	originalExtra := resp.Extra
	originalAnswer := resp.Answer
	originalNs := resp.Ns
	resp.SetReply(req)
	resp.Rcode = originalRcode   // Restore the original Rcode
	resp.Answer = originalAnswer // Restore the original Answer section
	resp.Ns = originalNs         // Restore the original Ns section
	resp.Extra = originalExtra   // Restore the original Extra section
	resp.Id = req.Id

	// Set Authoritative to false since this is from cache (matching V1 behavior)
	resp.Authoritative = false
	// RecursionAvailable is already preserved from the original message via MsgHdr copy

	// RFC 4035: Never set AD bit when CD bit is set in the request
	if req.CheckingDisabled {
		resp.AuthenticatedData = false
	}

	// Update TTLs
	ttl := uint32(remainingTTL)
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
	if e.hasEDE && req.IsEdns0() != nil {
		// Request has EDNS0, so we can add EDE to response
		opt := resp.IsEdns0()
		if opt == nil {
			// No OPT record in response, create one based on request
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

		// Add EDE to the OPT record
		ede := &dns.EDNS0_EDE{
			InfoCode:  e.edeCode,
			ExtraText: e.edeText,
		}
		opt.Option = append(opt.Option, ede)
	}

	return resp
}

// (*CacheEntry).IsExpired isExpired checks if the cache entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().Unix()-e.stored >= int64(e.ttl)
}

// (*CacheEntry).TTL TTL returns the remaining TTL in seconds.
func (e *CacheEntry) TTL() int {
	remaining := int64(e.ttl) - (time.Now().Unix() - e.stored)
	if remaining <= 0 {
		return 0
	}
	return int(remaining)
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

// HasEDE returns true if this entry has EDE information
func (e *CacheEntry) HasEDE() bool {
	return e.hasEDE
}

// GetEDECode returns the EDE code if present
func (e *CacheEntry) GetEDECode() uint16 {
	return e.edeCode
}

// CacheKey represents a structured cache key.
type CacheKey struct {
	Question dns.Question
	CD       bool
}

// (CacheKey).Hash hash returns the cache key hash.
func (k CacheKey) Hash() uint64 {
	return cache.Key(k.Question, k.CD)
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
}

// (*CacheMetrics).Miss miss records a cache miss.
func (m *CacheMetrics) Miss() {
	m.misses.Add(1)
}

// (*CacheMetrics).Eviction eviction records a cache eviction.
func (m *CacheMetrics) Eviction() {
	m.evictions.Add(1)
}

// (*CacheMetrics).Prefetch prefetch records a prefetch operation.
func (m *CacheMetrics) Prefetch() {
	m.prefetches.Add(1)
}

// (*CacheMetrics).Stats stats returns current metrics.
func (m *CacheMetrics) Stats() (hits, misses, evictions, prefetches int64) {
	return m.hits.Load(), m.misses.Load(), m.evictions.Load(), m.prefetches.Load()
}
