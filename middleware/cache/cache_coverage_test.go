package cache

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
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
		msg.SetReply(ch.Request.Msg())
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{8, 8, 8, 8},
		})
		ch.Writer.WriteMsg(msg) //nolint:gosec // G104 - test mock
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

	if stats == nil {
		t.Fatalf("stats is nil")
	}
	if _, ok := stats["hits"]; !ok {
		t.Errorf("stats %v missing %q", stats, "hits")
	}
	for _, key := range []string{"misses", "evictions", "prefetches", "positive_size", "negative_size", "hit_rate"} {
		if _, ok := stats[key]; !ok {
			t.Errorf("stats %v missing %q", stats, key)
		}
	}

	// Check positive size
	if !reflect.DeepEqual(1, stats["positive_size"]) {
		t.Errorf("stats['positive_size'] = %v, want %v", stats["positive_size"], 1)
	}
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

	if !reflect.DeepEqual(int64(2), hits) {
		t.Errorf("hits = %v, want %v", hits, int64(2))
	}
	if !reflect.DeepEqual(int64(1), misses) {
		t.Errorf("misses = %v, want %v", misses, int64(1))
	}
	if !reflect.DeepEqual(int64(3), evictions) {
		t.Errorf("evictions = %v, want %v", evictions, int64(3))
	}
	if !reflect.DeepEqual(int64(1), prefetches) {
		t.Errorf("prefetches = %v, want %v", prefetches, int64(1))
	}
}

// Test_Cache_Len tests Len methods.
func Test_Cache_Len(t *testing.T) {
	metrics := &CacheMetrics{}

	pc := NewPositiveCache(100, minTTL, maxTTL, metrics)
	nc := NewNegativeCache(100, time.Minute, time.Hour, metrics)

	// Initially empty
	if !reflect.DeepEqual(0, pc.Len()) {
		t.Errorf("pc.Len() = %v, want %v", pc.Len(), 0)
	}
	if !reflect.DeepEqual(0, nc.Len()) {
		t.Errorf("nc.Len() = %v, want %v", nc.Len(), 0)
	}

	// Add entries
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	entry := NewCacheEntry(req, time.Hour, 0)

	key := uint64(12345)
	pc.Set(key, entry)
	nc.Set(key, entry)

	if !reflect.DeepEqual(1, pc.Len()) {
		t.Errorf("pc.Len() = %v, want %v", pc.Len(), 1)
	}
	if !reflect.DeepEqual(1, nc.Len()) {
		t.Errorf("nc.Len() = %v, want %v", nc.Len(), 1)
	}
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
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}

	// Test with invalid query type
	req2 := new(dns.Msg)
	req2.SetQuestion("test.com.", 65535) // Invalid type
	req2.Question[0].Qclass = dns.ClassINET

	mw2 := mock.NewWriter("udp", "127.0.0.1:0")
	ch2 := middleware.NewChain([]middleware.Handler{})
	ch2.Reset(mw2, req2)
	c.ServeDNS(context.Background(), ch2)

	// Should cancel the request
	if mw2.Written() {
		t.Errorf("mw2.Written() is true")
	}
}

// Test_TTL_Manager tests TTL calculation edge cases.
func Test_TTL_Manager(t *testing.T) {
	ttl := NewTTLManager(time.Minute, time.Hour)

	// Test below minimum
	if !reflect.DeepEqual(time.Minute, ttl.Calculate(30*time.Second)) {
		t.Errorf("ttl.Calculate(30*time.Second) = %v, want %v", ttl.Calculate(30*time.Second), time.Minute)
	}

	// Test above maximum
	if !reflect.DeepEqual(time.Hour, ttl.Calculate(2*time.Hour)) {
		t.Errorf("ttl.Calculate(2*time.Hour) = %v, want %v", ttl.Calculate(2*time.Hour), time.Hour)
	}

	// Test within range
	if !reflect.DeepEqual(30*time.Minute, ttl.Calculate(30*time.Minute)) {
		t.Errorf("ttl.Calculate(30*time.Minute) = %v, want %v", ttl.Calculate(30*time.Minute), 30*time.Minute)
	}
}

// Test_Cache_Entry_Edge_Cases tests CacheEntry edge cases.
func Test_Cache_Entry_Edge_Cases(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	// Test expired entry
	entry := NewCacheEntry(req, 1*time.Millisecond, 0)
	time.Sleep(2 * time.Millisecond)

	if !(entry.IsExpired()) {
		t.Errorf("entry.IsExpired() is false")
	}
	if !reflect.DeepEqual(0, entry.TTL()) {
		t.Errorf("entry.TTL() = %v, want %v", entry.TTL(), 0)
	}
	if entry.ToMsg(req) != nil {
		t.Errorf("entry.ToMsg(req) = %v, want nil", entry.ToMsg(req))
	}

	// Test ShouldPrefetch with threshold 0
	entry2 := NewCacheEntry(req, time.Hour, 0)
	if entry2.ShouldPrefetch(0) {
		t.Errorf("entry2.ShouldPrefetch(0) is true")
	}

	// Test ShouldPrefetch when already prefetching
	entry2.prefetch.Store(true)
	if entry2.ShouldPrefetch(50) {
		t.Errorf("entry2.ShouldPrefetch(50) is true")
	}
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
	if !(added) {
		t.Errorf("added is false")
	}

	// Add second request immediately - queue should be full
	req2 := new(dns.Msg)
	req2.SetQuestion("test2.com.", dns.TypeA)
	added = queue.Add(PrefetchRequest{Request: req2, Key: 2})
	if added {
		t.Errorf("added is true")
	}
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

	if !(called) {
		t.Errorf("called is false")
	}
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
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Empty question should pass through
	res2 := new(dns.Msg)
	res2.SetReply(&dns.Msg{})
	res2.Question = []dns.Question{}

	err = w.WriteMsg(res2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
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
		nc.Set(uint64(i), entry) //nolint:gosec // G115 - test value
	}

	// Some entries should have been evicted
	// The exact number depends on the cache implementation
	if nc.Len() > 10 {
		t.Errorf("nc.Len() = %v, want <= %v", nc.Len(), 10)
	}
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

	if c == nil {
		t.Fatalf("c is nil")
	}
	if !reflect.DeepEqual(10, c.config.Prefetch) {
		t.Errorf("c.config.Prefetch = %v, want %v", c.config.Prefetch, 10)
	}

	// Test with prefetch > 90
	cfg2 := &config.Config{
		CacheSize: 1024,
		Expire:    600,
		Prefetch:  95,
	}

	c2 := New(cfg2)
	defer c2.Stop()

	// Should trigger validation warning but continue
	if c2 == nil {
		t.Fatalf("c2 is nil")
	}
}
