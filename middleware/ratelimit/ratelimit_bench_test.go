package ratelimit

import (
	"context"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
)

// BenchmarkRateLimitNormalTraffic tests performance with regular client IPs
func BenchmarkRateLimitNormalTraffic(b *testing.B) {
	cfg := &config.Config{
		ClientRateLimit: 100, // 100 queries per minute
	}
	rl := New(cfg)

	// Simulate 100 regular clients
	ips := make([]net.IP, 100)
	for i := range ips {
		ips[i] = net.IPv4(192, 168, 1, byte(i))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i%len(ips)]
			i++

			l := rl.getLimiter(ip)
			_ = l.rl.Allow()
		}
	})

	b.ReportMetric(float64(rl.store.Len()), "limiters")
}

// BenchmarkRateLimitRandomIPAttack tests performance under random IP attack
func BenchmarkRateLimitRandomIPAttack(b *testing.B) {
	cfg := &config.Config{
		ClientRateLimit: 100,
	}
	rl := New(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			// Generate random IP
			ip := net.IPv4(
				byte(r.Intn(256)),
				byte(r.Intn(256)),
				byte(r.Intn(256)),
				byte(r.Intn(256)),
			)

			l := rl.getLimiter(ip)
			_ = l.rl.Allow()
		}
	})

	b.ReportMetric(float64(rl.store.Len()), "limiters")
}

// BenchmarkRateLimitMixedTraffic tests with 90% normal + 10% attack traffic
func BenchmarkRateLimitMixedTraffic(b *testing.B) {
	cfg := &config.Config{
		ClientRateLimit: 100,
	}
	rl := New(cfg)

	// Regular clients
	regularIPs := make([]net.IP, 100)
	for i := range regularIPs {
		regularIPs[i] = net.IPv4(10, 0, 0, byte(i))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		i := 0
		for pb.Next() {
			var ip net.IP
			if r.Intn(10) < 9 { // 90% regular traffic
				ip = regularIPs[i%len(regularIPs)]
				i++
			} else { // 10% random IPs
				ip = net.IPv4(
					byte(r.Intn(256)),
					byte(r.Intn(256)),
					byte(r.Intn(256)),
					byte(r.Intn(256)),
				)
			}

			l := rl.getLimiter(ip)
			_ = l.rl.Allow()
		}
	})

	b.ReportMetric(float64(rl.store.Len()), "limiters")
}

// TestRateLimitEvictionPerformance tests eviction doesn't cause CPU spikes
func TestRateLimitEvictionPerformance(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 100,
	}
	rl := New(cfg)

	// Fill the cache to trigger evictions
	start := time.Now()
	for i := 0; i < cacheSize*2; i++ {
		ip := net.IPv4(
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
		_ = rl.getLimiter(ip)
	}
	elapsed := time.Since(start)

	// Should handle 51,200 IPs (2x cache size) quickly
	if elapsed > 1*time.Second {
		t.Errorf("Eviction too slow: %v for %d IPs", elapsed, cacheSize*2)
	}

	// Cache should be at max size
	if rl.store.Len() > cacheSize {
		t.Errorf("Cache size exceeded: %d > %d", rl.store.Len(), cacheSize)
	}

	t.Logf("Processed %d IPs in %v, cache size: %d", cacheSize*2, elapsed, rl.store.Len())
}

// TestRateLimitActualRateEnforcement tests that rate limiting actually works
func TestRateLimitActualRateEnforcement(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 60, // 60 per minute = 1 per second
	}
	rl := New(cfg)

	ip := net.IPv4(192, 168, 1, 1)
	limiter := rl.getLimiter(ip)

	allowed := 0
	blocked := 0

	// Try 100 requests rapidly
	for i := 0; i < 100; i++ {
		if limiter.rl.Allow() {
			allowed++
		} else {
			blocked++
		}
	}

	// Should allow burst (60) then block the rest
	if allowed > 65 || allowed < 55 {
		t.Errorf("Rate limit not working correctly: allowed=%d, blocked=%d", allowed, blocked)
	}

	t.Logf("Allowed: %d, Blocked: %d", allowed, blocked)
}

// TestRateLimitConcurrentAccess tests thread safety
func TestRateLimitConcurrentAccess(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 100,
	}
	rl := New(cfg)

	var wg sync.WaitGroup
	errors := atomic.Int32{}

	// 100 goroutines hitting the rate limiter
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errors.Add(1)
					t.Errorf("Panic in goroutine %d: %v", id, r)
				}
			}()

			for j := 0; j < 1000; j++ {
				ip := net.IPv4(192, 168, byte(id), byte(j%256))
				l := rl.getLimiter(ip)
				_ = l.rl.Allow()
			}
		}(i)
	}

	wg.Wait()

	if errors.Load() > 0 {
		t.Fatalf("Concurrent access caused %d panics", errors.Load())
	}
}

// TestRateLimitCleanup tests that old entries are cleaned up
func TestRateLimitCleanup(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 100,
	}
	rl := New(cfg)

	// Add some limiters
	for i := 0; i < 100; i++ {
		ip := net.IPv4(192, 168, 1, byte(i))
		_ = rl.getLimiter(ip)
	}

	initialSize := rl.store.Len()

	// Manually trigger cleanup of entries older than 1 nanosecond (all of them)
	time.Sleep(10 * time.Millisecond)
	rl.store.Cleanup(1 * time.Nanosecond)

	if rl.store.Len() != 0 {
		t.Errorf("Cleanup failed: %d limiters remaining", rl.store.Len())
	}

	t.Logf("Cleaned up %d limiters", initialSize)
}

// BenchmarkRateLimitServeDNS tests full middleware performance
func BenchmarkRateLimitServeDNS(b *testing.B) {
	cfg := &config.Config{
		ClientRateLimit: 1000, // High limit to avoid blocking in benchmark
	}
	rl := New(cfg)

	// Create mock chain
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			// Random IP to simulate attack
			ip := net.IPv4(
				byte(r.Intn(256)),
				byte(r.Intn(256)),
				byte(r.Intn(256)),
				byte(r.Intn(256)),
			)

			w := mock.NewWriter("udp", ip.String()+":53")

			ch := &middleware.Chain{
				Writer:  w,
				Request: req,
			}

			ctx := context.Background()
			rl.ServeDNS(ctx, ch)
		}
	})
}

// TestRateLimitMemoryUsage estimates memory usage
func TestRateLimitMemoryUsage(t *testing.T) {
	cfg := &config.Config{
		ClientRateLimit: 100,
	}
	rl := New(cfg)

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Fill cache completely
	for i := 0; i < cacheSize; i++ {
		ip := net.IPv4(
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
		_ = rl.getLimiter(ip)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	memUsed := m2.HeapAlloc - m1.HeapAlloc
	memPerEntry := memUsed / uint64(cacheSize)

	t.Logf("Memory usage: %d bytes total, ~%d bytes per limiter", memUsed, memPerEntry)

	// Each limiter should be reasonably small
	if memPerEntry > 500 {
		t.Errorf("Memory per limiter too high: %d bytes", memPerEntry)
	}
}

// Comparison benchmark with old cache-based approach (for reference)
func BenchmarkComparison(b *testing.B) {
	benchmarks := []struct {
		name string
		ips  func() net.IP
	}{
		{
			name: "SameIP",
			ips: func() net.IP {
				return net.IPv4(192, 168, 1, 1)
			},
		},
		{
			name: "100UniqueIPs",
			ips: func() net.IP {
				return net.IPv4(192, 168, 1, byte(rand.Intn(100)))
			},
		},
		{
			name: "RandomIPs",
			ips: func() net.IP {
				return net.IPv4(
					byte(rand.Intn(256)),
					byte(rand.Intn(256)),
					byte(rand.Intn(256)),
					byte(rand.Intn(256)),
				)
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			cfg := &config.Config{
				ClientRateLimit: 100,
			}
			rl := New(cfg)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ip := bm.ips()
				l := rl.getLimiter(ip)
				_ = l.rl.Allow()
			}
		})
	}
}
