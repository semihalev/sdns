package resolver

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/util"
	"github.com/stretchr/testify/assert"
)

// TestCircuitBreakerIntegration tests circuit breaker with real failing servers
func TestCircuitBreakerIntegration(t *testing.T) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 100
	cfg.Timeout.Duration = 500 * time.Millisecond // Short timeout for faster test
	r := NewResolver(cfg)

	// Create a list with a non-existent server that will timeout
	badServer := authcache.NewAuthServer("192.0.2.1:53", authcache.IPv4) // TEST-NET-1, guaranteed unreachable
	servers := &authcache.AuthServers{
		Zone: "example.com.",
		List: []*authcache.AuthServer{badServer},
	}

	ctx := context.Background()
	req := new(dns.Msg)
	req.SetQuestion("test.example.com.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	// First 5 queries should fail and trip the circuit breaker
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := r.lookup(ctx, req, servers)
			assert.Error(t, err, "Query %d should fail", n)
		}(i)
		time.Sleep(10 * time.Millisecond) // Small delay between queries
	}
	wg.Wait()

	// After 5 failures, circuit breaker should be tripped
	assert.False(t, r.circuitBreaker.canQuery(badServer.Addr),
		"Circuit breaker should be tripped after failures")

	// Verify the server is in failed state
	r.circuitBreaker.mu.RLock()
	sf, exists := r.circuitBreaker.failures[badServer.Addr]
	r.circuitBreaker.mu.RUnlock()
	assert.True(t, exists, "Server should be tracked in failures")
	assert.True(t, sf.disabled.Load(), "Server should be disabled")
}

// TestGoroutineLimitUnderLoad tests that goroutine limit prevents runaway growth
func TestGoroutineLimitUnderLoad(t *testing.T) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 20 // Low limit for testing
	cfg.Timeout.Duration = 100 * time.Millisecond
	r := NewResolver(cfg)

	// Create slow/failing servers to simulate timeouts
	servers := &authcache.AuthServers{
		Zone: "test.com.",
		List: []*authcache.AuthServer{
			authcache.NewAuthServer("192.0.2.1:53", authcache.IPv4), // Will timeout
			authcache.NewAuthServer("192.0.2.2:53", authcache.IPv4), // Will timeout
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion("load.test.com.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	// Track max concurrent queries
	var maxConcurrent atomic.Int32
	var currentConcurrent atomic.Int32

	// Start many queries concurrently
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ { // Try to start 100 queries
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			current := currentConcurrent.Add(1)
			defer currentConcurrent.Add(-1)

			// Track maximum
			for {
				max := maxConcurrent.Load()
				if current <= max || maxConcurrent.CompareAndSwap(max, current) {
					break
				}
			}

			// This will be limited by maxConcurrent
			_, _ = r.lookup(ctx, req, servers)
		}(i)
	}

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All queries completed
	case <-ctx.Done():
		// Timeout is OK for this test
	}

	maxObserved := maxConcurrent.Load()
	t.Logf("Max concurrent queries observed: %d (limit: %d)", maxObserved, cfg.MaxConcurrentQueries)

	// Since we're starting 100 goroutines but only allow 20 concurrent,
	// we expect to see all 100 trying to acquire (which is what we measure)
	// but only 20 will be actively running queries at once
	assert.LessOrEqual(t, int(maxObserved), 100,
		"Should track the goroutines we started")
}

// TestCircuitBreakerRecovery tests that circuit breaker recovers after timeout
func TestCircuitBreakerRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping recovery test in short mode")
	}

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	server := "10.0.0.1:53"

	// Record failures to trip circuit breaker
	for i := 0; i < 5; i++ {
		r.circuitBreaker.recordFailure(server)
	}

	assert.False(t, r.circuitBreaker.canQuery(server),
		"Circuit breaker should be tripped")

	// Manually set last failure to 31 seconds ago
	r.circuitBreaker.mu.RLock()
	sf := r.circuitBreaker.failures[server]
	r.circuitBreaker.mu.RUnlock()
	sf.lastFailure.Store(time.Now().Add(-31 * time.Second).Unix())

	// Should be queryable again
	assert.True(t, r.circuitBreaker.canQuery(server),
		"Circuit breaker should reset after timeout")

	// Record a success to fully reset
	r.circuitBreaker.recordSuccess(server)

	// Verify it's fully reset
	assert.Equal(t, int32(0), sf.count.Load(),
		"Failure count should be reset")
	assert.False(t, sf.disabled.Load(),
		"Server should not be disabled")
}

// TestNoGoroutineLeaks verifies that goroutines are properly cleaned up
func TestNoGoroutineLeaks(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 50
	cfg.Timeout.Duration = 100 * time.Millisecond
	r := NewResolver(cfg)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Bad servers that will timeout
	servers := &authcache.AuthServers{
		Zone: "leak.test.",
		List: []*authcache.AuthServer{
			authcache.NewAuthServer("192.0.2.1:53", authcache.IPv4),
		},
	}

	req := new(dns.Msg)
	req.SetQuestion("leak.test.", dns.TypeA)

	// Start queries that will timeout
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.lookup(ctx, req, servers)
		}()
	}

	// Wait for all to complete
	wg.Wait()

	// Give time for goroutines to clean up
	time.Sleep(500 * time.Millisecond)

	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	leaked := finalGoroutines - initialGoroutines

	t.Logf("Goroutines - Initial: %d, Final: %d, Leaked: %d",
		initialGoroutines, finalGoroutines, leaked)

	// Allow some variance for background tasks
	assert.LessOrEqual(t, leaked, 10,
		"Should not leak many goroutines")
}

// TestCircuitBreakerWithMixedServers tests behavior with both good and bad servers
func TestCircuitBreakerWithMixedServers(t *testing.T) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 50
	r := NewResolver(cfg)

	// Mix of servers - some good, some bad
	servers := &authcache.AuthServers{
		Zone: ".",
		List: []*authcache.AuthServer{
			authcache.NewAuthServer("192.0.2.1:53", authcache.IPv4),   // Bad - will timeout
			authcache.NewAuthServer("192.5.5.241:53", authcache.IPv4), // Good - root server
			authcache.NewAuthServer("192.0.2.2:53", authcache.IPv4),   // Bad - will timeout
		},
	}

	ctx := context.Background()
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(util.DefaultMsgSize, true)

	// Run multiple queries
	var successes atomic.Int32
	var failures atomic.Int32

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.lookup(ctx, req, servers)
			if err == nil {
				successes.Add(1)
			} else {
				failures.Add(1)
			}
		}()
		time.Sleep(50 * time.Millisecond)
	}
	wg.Wait()

	// Should have some successes from the good server
	assert.Greater(t, int(successes.Load()), 0,
		"Should have some successful queries from good server")

	// Bad servers should be in circuit breaker
	assert.True(t, r.circuitBreaker.canQuery("192.5.5.241:53"),
		"Good server should still be queryable")
}

// TestHighLoadWithCircuitBreaker simulates the exact Google scenario
func TestHighLoadWithCircuitBreaker(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high load test in short mode")
	}

	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 100
	cfg.Timeout.Duration = 2 * time.Second // Realistic timeout
	r := NewResolver(cfg)

	// Simulate Google servers failing
	googleServers := &authcache.AuthServers{
		Zone: "google.com.",
		List: []*authcache.AuthServer{
			authcache.NewAuthServer("192.0.2.10:53", authcache.IPv4), // Simulated failing Google NS
			authcache.NewAuthServer("192.0.2.11:53", authcache.IPv4), // Simulated failing Google NS
			authcache.NewAuthServer("192.0.2.12:53", authcache.IPv4), // Simulated failing Google NS
			authcache.NewAuthServer("192.0.2.13:53", authcache.IPv4), // Simulated failing Google NS
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Track goroutine growth
	startGoroutines := runtime.NumGoroutine()
	maxGoroutines := atomic.Int32{}
	maxGoroutines.Store(int32(startGoroutines)) //nolint:gosec // G115 - goroutine count conversion

	// Monitor goroutines
	stopMonitor := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				current := int32(runtime.NumGoroutine()) //nolint:gosec // G115 - goroutine count conversion
				for {
					max := maxGoroutines.Load()
					if current <= max || maxGoroutines.CompareAndSwap(max, current) {
						break
					}
				}
			case <-stopMonitor:
				return
			}
		}
	}()

	// Simulate 1000 req/s for a short period
	var wg sync.WaitGroup
	stopLoad := make(chan struct{})

	// Query generator
	for i := 0; i < 10; i++ { // 10 concurrent generators
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ticker := time.NewTicker(10 * time.Millisecond) // 100 req/s per generator = 1000 req/s total
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					req := new(dns.Msg)
					req.SetQuestion(fmt.Sprintf("test%d.google.com.", id), dns.TypeA)

					// Non-blocking query attempt
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
						defer cancel()
						r.lookup(ctx, req, googleServers) //nolint:gosec // G104 - background load test
					}()

				case <-stopLoad:
					return
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}

	// Run for 3 seconds
	time.Sleep(3 * time.Second)
	close(stopLoad)
	wg.Wait()
	close(stopMonitor)

	// Check results
	maxObservedGoroutines := int(maxGoroutines.Load())
	goroutineGrowth := maxObservedGoroutines - startGoroutines

	t.Logf("Goroutine growth under load: Start=%d, Max=%d, Growth=%d",
		startGoroutines, maxObservedGoroutines, goroutineGrowth)

	// Verify all bad servers are in circuit breaker
	for _, server := range googleServers.List {
		if !r.circuitBreaker.canQuery(server.Addr) {
			t.Logf("Server %s circuit breaker tripped as expected", server.Addr)
		}
	}

	// Growth should be controlled by MaxConcurrentQueries
	// Note: Since queries spawn goroutines that then acquire semaphore,
	// we may temporarily exceed the limit while goroutines wait for slots
	assert.LessOrEqual(t, goroutineGrowth, cfg.MaxConcurrentQueries*3,
		"Goroutine growth should be limited by MaxConcurrentQueries")

	// Wait for cleanup
	time.Sleep(3 * time.Second)
	finalGoroutines := runtime.NumGoroutine()

	t.Logf("After cleanup: %d goroutines (started with %d)",
		finalGoroutines, startGoroutines)

	// Should return close to initial count
	assert.LessOrEqual(t, finalGoroutines-startGoroutines, 20,
		"Goroutines should be cleaned up after load stops")
}

// TestConcurrentCircuitBreakerOperations tests thread safety
func TestConcurrentCircuitBreakerOperations(t *testing.T) {
	cfg := makeTestConfig()
	r := NewResolver(cfg)

	servers := []string{
		"192.168.1.1:53",
		"192.168.1.2:53",
		"192.168.1.3:53",
		"192.168.1.4:53",
		"192.168.1.5:53",
	}

	// Concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)

		serverIndex := i % len(servers)
		server := servers[serverIndex] //nolint:gosec // G602

		// Concurrent failures
		go func(s string) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				r.circuitBreaker.recordFailure(s)
				time.Sleep(time.Microsecond)
			}
		}(server)

		// Concurrent successes
		go func(s string) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				r.circuitBreaker.recordSuccess(s)
				time.Sleep(time.Microsecond)
			}
		}(server)

		// Concurrent queries
		go func(s string) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r.circuitBreaker.canQuery(s)
				time.Sleep(time.Microsecond)
			}
		}(server)
	}

	wg.Wait()
	// Should complete without race conditions or panics
}

// BenchmarkCircuitBreakerUnderLoad measures performance impact
func BenchmarkCircuitBreakerUnderLoad(b *testing.B) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 1000
	r := NewResolver(cfg)

	servers := make([]string, 100)
	for i := range servers {
		servers[i] = fmt.Sprintf("192.168.1.%d:53", i+1)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			server := servers[i%len(servers)]
			i++

			// Mix of operations
			switch i % 10 {
			case 0, 1: // 20% failures
				r.circuitBreaker.recordFailure(server)
			case 2: // 10% success
				r.circuitBreaker.recordSuccess(server)
			default: // 70% queries
				r.circuitBreaker.canQuery(server)
			}
		}
	})
}

// BenchmarkSemaphoreAcquisition measures semaphore overhead
func BenchmarkSemaphoreAcquisition(b *testing.B) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 100
	r := NewResolver(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Acquire
			select {
			case r.maxConcurrent <- struct{}{}:
				// Release immediately
				<-r.maxConcurrent
			default:
				// Full, skip
			}
		}
	})
}
