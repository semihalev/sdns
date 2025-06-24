package cache

import (
	"context"
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
)

func TestCache_Integration_Basic(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    600,
		Prefetch:  10,
		RateLimit: 10,
	}

	cache := New(cfg)
	defer cache.Stop()

	// Test cache name
	if cache.Name() != "cache" {
		t.Errorf("expected cache name, got %s", cache.Name())
	}

	// Create test query
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	// Test cache miss with proper handler that writes response
	t.Run("CacheMiss", func(t *testing.T) {
		w := mock.NewWriter("udp", "127.0.0.1:0")

		called := false
		nextHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			called = true
			// Simulate response - this is what resolver would do
			resp := new(dns.Msg)
			resp.SetReply(ch.Request)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(192, 0, 2, 1),
			})
			// Important: Write the response through the cache's ResponseWriter
			// This ensures the response is cached
			ch.Writer.WriteMsg(resp)
			ch.Cancel()
		})

		ch := middleware.NewChain([]middleware.Handler{cache, nextHandler})
		ch.Reset(w, req)

		// This simulates the full chain execution
		ch.Next(context.Background())

		if !called {
			t.Error("handler chain not called on cache miss")
		}

		if !w.Written() {
			t.Error("response not written on cache miss")
		}
	})

	// Test cache hit - should not go to next handler
	t.Run("CacheHit", func(t *testing.T) {
		w2 := mock.NewWriter("udp", "127.0.0.1:0")

		called := false
		nextHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			called = true
			t.Error("next handler should not be called on cache hit")
		})

		ch2 := middleware.NewChain([]middleware.Handler{cache, nextHandler})
		ch2.Reset(w2, req)

		// This should be served from cache
		ch2.Next(context.Background())

		if called {
			t.Error("handler chain called on cache hit")
		}

		if !w2.Written() {
			t.Error("no response written on cache hit")
		}

		// Verify we got the cached response
		resp := w2.Msg()
		if len(resp.Answer) != 1 {
			t.Errorf("expected 1 answer, got %d", len(resp.Answer))
		}
		if a, ok := resp.Answer[0].(*dns.A); ok {
			if !a.A.Equal([]byte{192, 0, 2, 1}) {
				t.Error("unexpected IP in cached response")
			}
		}
	})
}

func TestCache_Metrics(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    600,
	}

	cache := New(cfg)
	defer cache.Stop()

	// Create a fresh metrics instance to test with
	testMetrics := &CacheMetrics{}

	// Replace the cache metrics with our test instance
	cache.metrics = testMetrics
	cache.positive.metrics = testMetrics
	cache.negative.metrics = testMetrics

	// Generate some cache activity using the public API
	for i := 0; i < 10; i++ {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("test%d.com.", i), dns.TypeA)

		// Simulate cache miss then hit
		w := mock.NewWriter("udp", "127.0.0.1:0")

		// First request - cache miss
		nextHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			resp := new(dns.Msg)
			resp.SetReply(ch.Request)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   ch.Request.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: []byte{192, 0, 2, byte(i)},
			})
			ch.Writer.WriteMsg(resp)
			ch.Cancel()
		})

		ch := middleware.NewChain([]middleware.Handler{cache, nextHandler})
		ch.Reset(w, req)
		ch.Next(context.Background())

		// Second request - cache hit
		w2 := mock.NewWriter("udp", "127.0.0.1:0")
		ch2 := middleware.NewChain([]middleware.Handler{cache})
		ch2.Reset(w2, req)
		ch2.Next(context.Background())
	}

	// Check metrics
	hits, misses, _, _ := testMetrics.Stats()

	if hits != 10 {
		t.Errorf("expected 10 hits, got %d", hits)
	}

	// Each cache miss checks both positive and negative caches, so we get 2 misses per request
	if misses != 20 {
		t.Errorf("expected 20 misses (2 per request), got %d", misses)
	}

	// Test cache stats
	stats := cache.Stats()

	if stats["hits"] != int64(10) {
		t.Errorf("expected stats hits=10, got %v", stats["hits"])
	}

	if stats["misses"] != int64(20) {
		t.Errorf("expected stats misses=20, got %v", stats["misses"])
	}

	hitRate, ok := stats["hit_rate"].(float64)
	if !ok {
		t.Error("hit_rate not found in stats")
	} else {
		// With 10 hits and 20 misses, hit rate should be 10/30 = 33.33%
		expectedRate := (10.0 / 30.0) * 100
		if math.Abs(hitRate-expectedRate) > 0.01 {
			t.Errorf("expected hit rate %.2f%%, got %.2f%%", expectedRate, hitRate)
		}
	}
}

func TestCache_Prefetch(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    600,
		Prefetch:  50, // 50% of TTL
		RateLimit: 0,
	}

	cache := New(cfg)
	defer cache.Stop()

	// Create a short-lived cache entry manually
	req := new(dns.Msg)
	req.SetQuestion("prefetch-test.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "prefetch-test.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    5,
		},
		A: net.IPv4(192, 0, 2, 1),
	})

	// Create cache entry with 5 second TTL
	// Make sure to use the exact same question format as in the request
	question := req.Question[0]
	key := CacheKey{Question: question, CD: false}.Hash()
	entry := NewCacheEntry(resp, 5*time.Second, 0)
	if entry == nil {
		t.Fatal("failed to create cache entry")
	}
	cache.positive.Set(key, entry)

	// Verify entry was set
	testEntry, ok := cache.positive.Get(key)
	if !ok {
		t.Fatal("entry was not set in cache")
	}
	if testEntry == nil {
		t.Fatal("cache returned nil entry")
	}

	// Wait until we're in prefetch window (>50% of TTL elapsed)
	// With 5s TTL and 50% threshold, prefetch happens when TTL <= 2.5s
	// So we need to wait at least 2.5s - wait 3s to be safe
	time.Sleep(3 * time.Second)

	// This request should trigger prefetch
	w := mock.NewWriter("udp", "127.0.0.1:0")

	// Add a handler that will be called if cache miss occurs
	nextHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		// Return empty response for cache miss
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		ch.Writer.WriteMsg(resp)
	})

	ch := middleware.NewChain([]middleware.Handler{cache, nextHandler})
	ch.Reset(w, req)
	ch.Next(context.Background())

	if !w.Written() {
		t.Error("no response written")
	}

	// Check if the entry was marked for prefetch
	updatedEntry, ok := cache.positive.Get(key)
	if !ok {
		t.Error("entry not found in cache after request")
	} else if !updatedEntry.prefetch.Load() {
		// Add debug info when prefetch is not marked
		t.Errorf("entry should be marked for prefetch (TTL: %d, origTTL: %d, threshold: %d)",
			updatedEntry.TTL(), updatedEntry.origTTL, cfg.Prefetch)
	}

	// Note: We can't test actual prefetch execution in unit tests
	// because it requires dnsutil.ExchangeInternal which needs a full resolver chain
	// The actual prefetch functionality is tested in integration/e2e tests
}

func TestCache_CNAMEChain(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    600,
	}

	cache := New(cfg)
	defer cache.Stop()

	// First request - populate cache with CNAME
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)

	w := mock.NewWriter("udp", "127.0.0.1:0")

	nextHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)

		// Return CNAME pointing to example.com
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   "www.example.com.",
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: "example.com.",
		})

		ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	ch := middleware.NewChain([]middleware.Handler{cache, nextHandler})
	ch.Reset(w, req)
	ch.Next(context.Background())

	// Now populate cache with A record for example.com
	req2 := new(dns.Msg)
	req2.SetQuestion("example.com.", dns.TypeA)

	w2 := mock.NewWriter("udp", "127.0.0.1:0")

	nextHandler2 := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(192, 0, 2, 1),
		})
		ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	ch2 := middleware.NewChain([]middleware.Handler{cache, nextHandler2})
	ch2.Reset(w2, req2)
	ch2.Next(context.Background())

	// Now query for www.example.com again - should get CNAME + A from cache
	w3 := mock.NewWriter("udp", "127.0.0.1:0")
	ch3 := middleware.NewChain([]middleware.Handler{cache})
	ch3.Reset(w3, req)
	ch3.Next(context.Background())

	if !w3.Written() {
		t.Error("no response written")
	}

	resp := w3.Msg()
	if len(resp.Answer) < 1 {
		t.Error("expected at least CNAME in response")
	}

	// Should have CNAME as first answer
	if cname, ok := resp.Answer[0].(*dns.CNAME); !ok || cname.Target != "example.com." {
		t.Error("expected CNAME record first")
	}
}
