package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

// TestRateLimitEnforcement verifies rate limiting works correctly
func TestRateLimitEnforcement(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 5, // 5 requests per minute
	}

	rl := New(cfg)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	// Helper function to test if request is allowed
	testRequest := func(ip string) bool {
		mw := mock.NewWriter("udp", ip)

		// Add a dummy handler to check if chain proceeds
		allowed := false
		dummyHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			allowed = true
			ch.Next(ctx)
		})

		ch := middleware.NewChain([]middleware.Handler{dummyHandler})
		ch.Reset(mw, req)

		rl.ServeDNS(context.Background(), ch)
		return allowed // Return true if the dummy handler was called
	}

	// Test burst allowance
	t.Run("BurstAllowance", func(t *testing.T) {
		ip := "10.0.0.1:53"

		// First 5 should be allowed (burst size)
		for i := 0; i < 5; i++ {
			assert.True(t, testRequest(ip), "Request %d should be allowed", i+1)
		}

		// 6th should be blocked
		assert.False(t, testRequest(ip), "6th request should be blocked")
	})

	// Test different IPs have separate limits
	t.Run("SeparateLimits", func(t *testing.T) {
		// Each IP should get its own 5 request burst
		for i := 1; i <= 3; i++ {
			ip := fmt.Sprintf("10.0.1.%d:53", i)

			// Each IP should get 5 requests
			for j := 0; j < 5; j++ {
				assert.True(t, testRequest(ip), "IP %s request %d should be allowed", ip, j+1)
			}

			// 6th should be blocked
			assert.False(t, testRequest(ip), "IP %s 6th request should be blocked", ip)
		}
	})

	// Test rate recovery
	t.Run("RateRecovery", func(t *testing.T) {
		ip := "10.0.2.1:53"

		// Use up the burst
		for i := 0; i < 5; i++ {
			assert.True(t, testRequest(ip), "Initial request %d should be allowed", i+1)
		}

		// Should be blocked now
		assert.False(t, testRequest(ip), "Should be rate limited after burst")

		// Wait for one token to regenerate (5 per minute = 12 seconds per token)
		time.Sleep(13 * time.Second)

		// Should allow one more
		assert.True(t, testRequest(ip), "Should allow after token regeneration")

		// But not two
		assert.False(t, testRequest(ip), "Should block again after using regenerated token")
	})
}

// TestRateLimitBypassConditions tests scenarios that bypass rate limiting
func TestRateLimitBypassConditions(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 1, // Very restrictive
	}

	rl := New(cfg)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	// Test no IP bypass (empty remote address)
	t.Run("NoIPBypass", func(t *testing.T) {
		// Mock writer with no IP address
		mw := mock.NewWriter("udp", "")

		for i := 0; i < 10; i++ {
			allowed := false
			dummyHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
				allowed = true
				ch.Next(ctx)
			})

			ch := middleware.NewChain([]middleware.Handler{dummyHandler})
			ch.Reset(mw, req)

			rl.ServeDNS(context.Background(), ch)
			assert.True(t, allowed, "Request %d with no IP should bypass rate limit", i+1)
		}
	})

	// Test loopback bypass
	t.Run("LoopbackBypass", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			mw := mock.NewWriter("udp", "127.0.0.1:53")

			allowed := false
			dummyHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
				allowed = true
				ch.Next(ctx)
			})

			ch := middleware.NewChain([]middleware.Handler{dummyHandler})
			ch.Reset(mw, req)

			rl.ServeDNS(context.Background(), ch)
			assert.True(t, allowed, "Loopback request %d should not be rate limited", i+1)
		}
	})

	// Test disabled rate limiting (rate = 0)
	t.Run("DisabledRateLimit", func(t *testing.T) {
		rl.rate = 0 // Disable rate limiting

		for i := 0; i < 100; i++ {
			mw := mock.NewWriter("udp", fmt.Sprintf("10.1.1.%d:53", i))

			allowed := false
			dummyHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
				allowed = true
				ch.Next(ctx)
			})

			ch := middleware.NewChain([]middleware.Handler{dummyHandler})
			ch.Reset(mw, req)

			rl.ServeDNS(context.Background(), ch)
			assert.True(t, allowed, "Request %d should not be limited when rate=0", i+1)
		}

		rl.rate = 1 // Re-enable for other tests
	})
}

// TestRateLimitConcurrency tests thread safety under concurrent access
func TestRateLimitConcurrency(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 100, // Higher limit for concurrency test
	}

	rl := New(cfg)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	var wg sync.WaitGroup
	errors := atomic.Int32{}

	// 50 concurrent goroutines
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errors.Add(1)
					t.Errorf("Panic in goroutine %d: %v", id, r)
				}
			}()

			// Each goroutine makes 100 requests
			for j := 0; j < 100; j++ {
				ip := fmt.Sprintf("10.2.%d.%d:53", id, j%256)
				mw := mock.NewWriter("udp", ip)
				ch := middleware.NewChain([]middleware.Handler{})
				ch.Reset(mw, req)

				rl.ServeDNS(context.Background(), ch)
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, int32(0), errors.Load(), "Should handle concurrent access without errors")
}

// TestRateLimitStoreCleanup verifies old limiters are cleaned up
func TestRateLimitStoreCleanup(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 10,
	}

	rl := New(cfg)

	// Add some limiters
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.3.0.%d:53", i)
		mw := mock.NewWriter("udp", ip)
		ch := middleware.NewChain([]middleware.Handler{})
		ch.Reset(mw, new(dns.Msg))
		rl.ServeDNS(context.Background(), ch)
	}

	initialCount := rl.store.Len()
	assert.Equal(t, 100, initialCount, "Should have 100 limiters")

	// Wait a bit and trigger cleanup
	time.Sleep(100 * time.Millisecond)
	rl.store.Cleanup(50 * time.Millisecond)

	finalCount := rl.store.Len()
	assert.Equal(t, 0, finalCount, "All limiters should be cleaned up")
}

// TestRateLimitPerformanceUnderAttack simulates attack conditions
func TestRateLimitPerformanceUnderAttack(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 10,
	}

	rl := New(cfg)
	req := new(dns.Msg)
	req.SetQuestion("attack.test.", dns.TypeA)

	start := time.Now()

	// Simulate 100,000 requests from random IPs
	for i := 0; i < 100000; i++ {
		ip := fmt.Sprintf("%d.%d.%d.%d:53",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)

		mw := mock.NewWriter("udp", ip)
		ch := middleware.NewChain([]middleware.Handler{})
		ch.Reset(mw, req)

		rl.ServeDNS(context.Background(), ch)
	}

	elapsed := time.Since(start)

	// Should handle 100k requests quickly even under attack
	assert.Less(t, elapsed, 5*time.Second, "Should handle 100k requests in < 5 seconds")

	// Cache should not exceed limit
	assert.LessOrEqual(t, rl.store.Len(), cacheSize, "Cache should not exceed size limit")

	t.Logf("Processed 100k attack requests in %v, cache size: %d", elapsed, rl.store.Len())
}
