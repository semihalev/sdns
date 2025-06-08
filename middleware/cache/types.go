package cache

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"golang.org/x/time/rate"
)

// DNSCache defines the interface for DNS cache implementations
type DNSCache interface {
	Get(key uint64) (*CacheEntry, bool)
	Set(key uint64, entry *CacheEntry)
	Remove(key uint64)
	Len() int
}

// CacheEntry represents an immutable cache entry
type CacheEntry struct {
	msg      *dns.Msg
	stored   time.Time
	ttl      time.Duration
	origTTL  uint32 // Original TTL in seconds for prefetch calculation
	prefetch atomic.Bool
	limiter  *rate.Limiter
	ede      *dns.EDNS0_EDE // Preserved EDE information
}

// NewCacheEntry creates a new cache entry from a DNS message
func NewCacheEntry(msg *dns.Msg, ttl time.Duration, rateLimit int) *CacheEntry {
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
		msg:     msgCopy,
		stored:  time.Now().UTC(),
		ttl:     ttl,
		origTTL: uint32(ttl.Seconds()),
		ede:     ede,
	}

	if rateLimit > 0 {
		limit := rate.Every(time.Second / time.Duration(rateLimit))
		entry.limiter = rate.NewLimiter(limit, rateLimit)
	}

	return entry
}

// ToMsg creates a response message with updated TTLs
func (e *CacheEntry) ToMsg(req *dns.Msg) *dns.Msg {
	now := time.Now().UTC()
	elapsed := now.Sub(e.stored)
	remainingTTL := e.ttl - elapsed

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
	if e.ede != nil && resp.Rcode == dns.RcodeServerFailure {
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

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Since(e.stored) >= e.ttl
}

// TTL returns the remaining TTL in seconds
func (e *CacheEntry) TTL() int {
	remaining := e.ttl - time.Since(e.stored)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Seconds())
}

// ShouldPrefetch checks if this entry should be prefetched
func (e *CacheEntry) ShouldPrefetch(threshold int) bool {
	if threshold <= 0 || e.prefetch.Load() {
		return false
	}

	// Calculate based on original TTL (matching V1 behavior)
	remainingTTL := e.TTL()
	thresholdSeconds := int(float64(threshold) / 100.0 * float64(e.origTTL))
	return remainingTTL <= thresholdSeconds
}

// CacheKey represents a structured cache key
type CacheKey struct {
	Question dns.Question
	CD       bool
}

// Hash returns the cache key hash
func (k CacheKey) Hash() uint64 {
	return cache.Key(k.Question, k.CD)
}

// CacheConfig holds cache configuration with validation
type CacheConfig struct {
	Size        int
	Prefetch    int
	PositiveTTL time.Duration
	NegativeTTL time.Duration
	MinTTL      time.Duration
	MaxTTL      time.Duration
	RateLimit   int
}

// Validate checks if the configuration is valid
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

// TTLManager manages TTL calculations
type TTLManager struct {
	min, max time.Duration
}

// NewTTLManager creates a new TTL manager
func NewTTLManager(min, max time.Duration) TTLManager {
	return TTLManager{min: min, max: max}
}

// Calculate returns the effective TTL within configured bounds
func (tm TTLManager) Calculate(msgTTL time.Duration) time.Duration {
	if msgTTL < tm.min {
		return tm.min
	}
	if msgTTL > tm.max {
		return tm.max
	}
	return msgTTL
}

// CacheMetrics tracks cache performance metrics
type CacheMetrics struct {
	hits       atomic.Int64
	misses     atomic.Int64
	evictions  atomic.Int64
	prefetches atomic.Int64
}

// Hit records a cache hit
func (m *CacheMetrics) Hit() {
	m.hits.Add(1)
}

// Miss records a cache miss
func (m *CacheMetrics) Miss() {
	m.misses.Add(1)
}

// Eviction records a cache eviction
func (m *CacheMetrics) Eviction() {
	m.evictions.Add(1)
}

// Prefetch records a prefetch operation
func (m *CacheMetrics) Prefetch() {
	m.prefetches.Add(1)
}

// Stats returns current metrics
func (m *CacheMetrics) Stats() (hits, misses, evictions, prefetches int64) {
	return m.hits.Load(), m.misses.Load(), m.evictions.Load(), m.prefetches.Load()
}
