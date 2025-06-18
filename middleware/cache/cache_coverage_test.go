package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

// Test_Cache_Stats tests the Stats method.
func Test_Cache_Stats(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    600,
		Prefetch:  20,
	}

	c := New(cfg)
	defer c.Stop()

	// Generate some cache activity
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	// First request - cache miss
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	mockHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		msg := new(dns.Msg)
		msg.SetReply(ch.Request)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{8, 8, 8, 8},
		})
		ch.Writer.WriteMsg(msg)
		ch.Cancel()
	})

	ch := middleware.NewChain([]middleware.Handler{c, mockHandler})
	ch.Reset(mw, req)
	ch.Next(context.Background())

	// Second request - cache hit
	mw2 := mock.NewWriter("udp", "127.0.0.1:0")
	ch2 := middleware.NewChain([]middleware.Handler{c})
	ch2.Reset(mw2, req)
	ch2.Next(context.Background())

	// Get stats
	stats := c.Stats()

	assert.NotNil(t, stats)
	assert.Contains(t, stats, "hits")
	assert.Contains(t, stats, "misses")
	assert.Contains(t, stats, "evictions")
	assert.Contains(t, stats, "prefetches")
	assert.Contains(t, stats, "positive_size")
	assert.Contains(t, stats, "negative_size")
	assert.Contains(t, stats, "hit_rate")

	// Check positive size
	assert.Equal(t, 1, stats["positive_size"])
}

// Test_Cache_Metrics_All tests all metric methods.
func Test_Cache_Metrics_All(t *testing.T) {
	m := &CacheMetrics{}

	// Test all metric recording methods
	m.Hit()
	m.Hit()
	m.Miss()
	m.Eviction()
	m.Eviction()
	m.Eviction()
	m.Prefetch()

	hits, misses, evictions, prefetches := m.Stats()

	assert.Equal(t, int64(2), hits)
	assert.Equal(t, int64(1), misses)
	assert.Equal(t, int64(3), evictions)
	assert.Equal(t, int64(1), prefetches)
}

// Test_Cache_Len tests Len methods.
func Test_Cache_Len(t *testing.T) {
	metrics := &CacheMetrics{}

	pc := NewPositiveCache(100, minTTL, maxTTL, metrics)
	nc := NewNegativeCache(100, time.Minute, time.Hour, metrics)

	// Initially empty
	assert.Equal(t, 0, pc.Len())
	assert.Equal(t, 0, nc.Len())

	// Add entries
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	entry := NewCacheEntry(req, time.Hour, 0)

	key := uint64(12345)
	pc.Set(key, entry)
	nc.Set(key, entry)

	assert.Equal(t, 1, pc.Len())
	assert.Equal(t, 1, nc.Len())
}

// Test_Cache_InvalidQueries tests handling of invalid queries.
func Test_Cache_InvalidQueries(t *testing.T) {
	cfg := &config.Config{CacheSize: 1024, Expire: 600}
	c := New(cfg)
	defer c.Stop()

	mw := mock.NewWriter("udp", "127.0.0.1:0")

	// Test with invalid query class
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.Question[0].Qclass = 65535 // Invalid class

	// Call ServeDNS directly to test cache behavior
	ch := middleware.NewChain([]middleware.Handler{})
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)

	// Should cancel the request
	assert.False(t, mw.Written())

	// Test with invalid query type
	req2 := new(dns.Msg)
	req2.SetQuestion("test.com.", 65535) // Invalid type
	req2.Question[0].Qclass = dns.ClassINET

	mw2 := mock.NewWriter("udp", "127.0.0.1:0")
	ch2 := middleware.NewChain([]middleware.Handler{})
	ch2.Reset(mw2, req2)
	c.ServeDNS(context.Background(), ch2)

	// Should cancel the request
	assert.False(t, mw2.Written())
}

// Test_TTL_Manager tests TTL calculation edge cases.
func Test_TTL_Manager(t *testing.T) {
	ttl := NewTTLManager(time.Minute, time.Hour)

	// Test below minimum
	assert.Equal(t, time.Minute, ttl.Calculate(30*time.Second))

	// Test above maximum
	assert.Equal(t, time.Hour, ttl.Calculate(2*time.Hour))

	// Test within range
	assert.Equal(t, 30*time.Minute, ttl.Calculate(30*time.Minute))
}

// Test_Cache_Entry_Edge_Cases tests CacheEntry edge cases.
func Test_Cache_Entry_Edge_Cases(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	// Test expired entry
	entry := NewCacheEntry(req, 1*time.Millisecond, 0)
	time.Sleep(2 * time.Millisecond)

	assert.True(t, entry.IsExpired())
	assert.Equal(t, 0, entry.TTL())
	assert.Nil(t, entry.ToMsg(req))

	// Test ShouldPrefetch with threshold 0
	entry2 := NewCacheEntry(req, time.Hour, 0)
	assert.False(t, entry2.ShouldPrefetch(0))

	// Test ShouldPrefetch when already prefetching
	entry2.prefetch.Store(true)
	assert.False(t, entry2.ShouldPrefetch(50))
}

// Test_Prefetch_Queue_Full tests prefetch queue when full.
func Test_Prefetch_Queue_Full(t *testing.T) {
	metrics := &CacheMetrics{}
	// Create a queue with size 1 but 0 workers to prevent processing
	queue := &PrefetchQueue{
		items:   make(chan PrefetchRequest, 1),
		workers: 0,
		metrics: metrics,
	}

	req := new(dns.Msg)
	req.SetQuestion("test1.com.", dns.TypeA)

	// Add first request - should succeed
	added := queue.Add(PrefetchRequest{Request: req, Key: 1})
	assert.True(t, added)

	// Add second request immediately - queue should be full
	req2 := new(dns.Msg)
	req2.SetQuestion("test2.com.", dns.TypeA)
	added = queue.Add(PrefetchRequest{Request: req2, Key: 2})
	assert.False(t, added)
}

// Test_Release_Msg_Large tests ReleaseMsg with large message.
func Test_Release_Msg_Large(t *testing.T) {
	m := AcquireMsg()

	// Make the message too large for the pool
	for i := 0; i < 200; i++ {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{1, 2, 3, 4},
		})
	}

	// Should not panic
	ReleaseMsg(m)
}

// Test_Handle_Special_Query_DebugNS tests debug query handling.
func Test_Handle_Special_Query_DebugNS(t *testing.T) {
	// Temporarily enable debugns
	oldDebugns := debugns
	debugns = true
	defer func() { debugns = oldDebugns }()

	cfg := &config.Config{CacheSize: 1024, Expire: 600}
	c := New(cfg)
	defer c.Stop()

	called := false
	nextHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		called = true
		ch.Cancel()
	})

	ch := middleware.NewChain([]middleware.Handler{c, nextHandler})

	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeHINFO)
	req.Question[0].Qclass = dns.ClassCHAOS

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	c.ServeDNS(context.Background(), ch)

	assert.True(t, called)
}

// Test_WriteMsg_Truncated tests WriteMsg with truncated response.
func Test_WriteMsg_Truncated(t *testing.T) {
	cfg := &config.Config{CacheSize: 1024, Expire: 600}
	c := New(cfg)
	defer c.Stop()

	w := &ResponseWriter{
		ResponseWriter: mock.NewWriter("udp", "127.0.0.1:0"),
		cache:          c,
	}

	// Truncated response should pass through
	res := new(dns.Msg)
	res.SetReply(&dns.Msg{Question: []dns.Question{{Name: "test.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	res.Truncated = true

	err := w.WriteMsg(res)
	assert.NoError(t, err)

	// Empty question should pass through
	res2 := new(dns.Msg)
	res2.SetReply(&dns.Msg{})
	res2.Question = []dns.Question{}

	err = w.WriteMsg(res2)
	assert.NoError(t, err)
}

// Test_Negative_Cache_Eviction tests negative cache with eviction.
func Test_Negative_Cache_Eviction(t *testing.T) {
	metrics := &CacheMetrics{}
	nc := NewNegativeCache(10, time.Minute, time.Hour, metrics)

	// Fill the cache beyond capacity
	for i := 0; i < 20; i++ {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("test%d.com.", i), dns.TypeA)
		entry := NewCacheEntry(req, time.Hour, 0)
		nc.Set(uint64(i), entry)
	}

	// Some entries should have been evicted
	// The exact number depends on the cache implementation
	assert.LessOrEqual(t, nc.Len(), 10)
}

// Test_Config_Edge_Cases tests configuration edge cases.
func Test_Config_Edge_Cases(t *testing.T) {
	// Test with very small cache size - should be adjusted
	cfg := &config.Config{
		CacheSize: 100,
		Expire:    600,
		Prefetch:  5, // Should be adjusted to 10
	}

	c := New(cfg)
	defer c.Stop()

	assert.NotNil(t, c)
	assert.Equal(t, 10, c.config.Prefetch)

	// Test with prefetch > 90
	cfg2 := &config.Config{
		CacheSize: 1024,
		Expire:    600,
		Prefetch:  95,
	}

	c2 := New(cfg2)
	defer c2.Stop()

	// Should trigger validation warning but continue
	assert.NotNil(t, c2)
}
