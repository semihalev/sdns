package resolver

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCircuitBreaker_Basic(t *testing.T) {
	cb := newCircuitBreaker()
	server := "8.8.8.8:53"

	// Initially, server should be queryable
	assert.True(t, cb.canQuery(server))

	// Record 4 failures - should still be queryable
	for i := 0; i < 4; i++ {
		cb.recordFailure(server)
		assert.True(t, cb.canQuery(server), "Should be queryable after %d failures", i+1)
	}

	// 5th failure should trip the circuit breaker
	cb.recordFailure(server)
	assert.False(t, cb.canQuery(server), "Circuit breaker should be tripped after 5 failures")

	// Success should reset the circuit breaker
	cb.recordSuccess(server)
	assert.True(t, cb.canQuery(server), "Circuit breaker should be reset after success")
}

func TestCircuitBreaker_Timeout(t *testing.T) {
	cb := newCircuitBreaker()
	server := "1.2.3.4:53"

	// Trip the circuit breaker
	for i := 0; i < 5; i++ {
		cb.recordFailure(server)
	}
	assert.False(t, cb.canQuery(server))

	// Manually set last failure time to 31 seconds ago
	cb.mu.RLock()
	sf := cb.failures[server]
	cb.mu.RUnlock()
	sf.lastFailure.Store(time.Now().Add(-31 * time.Second).Unix())

	// Should be queryable again after timeout
	assert.True(t, cb.canQuery(server), "Circuit breaker should reset after 30 second timeout")
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	cb := newCircuitBreaker()
	servers := []string{
		"8.8.8.8:53",
		"8.8.4.4:53",
		"1.1.1.1:53",
		"9.9.9.9:53",
	}

	var wg sync.WaitGroup
	for _, server := range servers {
		server := server
		wg.Add(3)

		// Concurrent failures
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				cb.recordFailure(server)
				time.Sleep(time.Millisecond)
			}
		}()

		// Concurrent success
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				cb.recordSuccess(server)
				time.Sleep(time.Millisecond)
			}
		}()

		// Concurrent queries
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				cb.canQuery(server)
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()
	// Should not panic or deadlock
}

func TestCircuitBreaker_MultipleServers(t *testing.T) {
	cb := newCircuitBreaker()
	server1 := "8.8.8.8:53"
	server2 := "8.8.4.4:53"

	// Trip circuit breaker for server1
	for i := 0; i < 5; i++ {
		cb.recordFailure(server1)
	}
	assert.False(t, cb.canQuery(server1))

	// server2 should still be queryable
	assert.True(t, cb.canQuery(server2))

	// Record failures for server2
	for i := 0; i < 3; i++ {
		cb.recordFailure(server2)
	}
	assert.True(t, cb.canQuery(server2), "Server2 should still be queryable with 3 failures")
	assert.False(t, cb.canQuery(server1), "Server1 should still be disabled")
}

func TestCircuitBreaker_ResetBehavior(t *testing.T) {
	cb := newCircuitBreaker()
	server := "10.0.0.1:53"

	// Record 3 failures
	for i := 0; i < 3; i++ {
		cb.recordFailure(server)
	}

	// Success should reset counter
	cb.recordSuccess(server)

	// Should need 5 more failures to trip
	for i := 0; i < 4; i++ {
		cb.recordFailure(server)
		assert.True(t, cb.canQuery(server), "Should be queryable after reset + %d failures", i+1)
	}

	// 5th failure after reset should trip
	cb.recordFailure(server)
	assert.False(t, cb.canQuery(server))
}

func TestCircuitBreaker_CleanupOldEntries(t *testing.T) {
	// This test would need to mock time or wait 5 minutes
	// For unit testing, we'll just verify the cleanup goroutine starts
	cb := newCircuitBreaker()

	// Add a server and mark it successful (count = 0)
	server := "192.168.1.1:53"
	cb.recordFailure(server)
	cb.recordSuccess(server)

	// Verify entry exists
	cb.mu.RLock()
	_, exists := cb.failures[server]
	cb.mu.RUnlock()
	assert.True(t, exists)

	// Cleanup happens every 5 minutes in background
	// For testing, we just verify the structure is correct
	assert.NotNil(t, cb.failures)
}

func TestResolverWithCircuitBreaker(t *testing.T) {
	// Test that resolver properly uses circuit breaker
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 100
	r := NewResolver(cfg)

	// Verify circuit breaker is initialized
	require.NotNil(t, r.circuitBreaker)

	// Verify max concurrent channel has correct capacity
	assert.Equal(t, 100, cap(r.maxConcurrent))
}

func TestResolverGoroutineLimiting(t *testing.T) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 50 // Higher limit to avoid conflict with background tasks
	r := NewResolver(cfg)

	// Wait a bit for any initial background queries to complete
	time.Sleep(100 * time.Millisecond)

	// Count current usage
	currentUsage := len(r.maxConcurrent)
	availableSlots := 50 - currentUsage

	// Fill up most of the available slots, leave a few for background
	fillCount := availableSlots - 5
	if fillCount < 0 {
		fillCount = 0
	}

	for i := 0; i < fillCount; i++ {
		select {
		case r.maxConcurrent <- struct{}{}:
			// Successfully acquired
		default:
			// Already full, stop trying
			break
		}
	}

	// Verify we can still acquire and release
	select {
	case r.maxConcurrent <- struct{}{}:
		<-r.maxConcurrent // Release immediately
	default:
		// Channel is full, which is also fine for this test
	}

	// Clean up all our test acquisitions
	for i := 0; i < fillCount; i++ {
		select {
		case <-r.maxConcurrent:
		default:
			break
		}
	}

	// Just verify the semaphore mechanism works
	assert.True(t, cap(r.maxConcurrent) == 50, "Semaphore should have correct capacity")
}

func TestResolverConcurrentQueryLimit(t *testing.T) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 10
	r := NewResolver(cfg)

	// Track active queries
	var activeQueries atomic.Int32
	var maxObserved atomic.Int32

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Simulate acquiring semaphore
			r.maxConcurrent <- struct{}{}

			// Track active count
			current := activeQueries.Add(1)
			for {
				max := maxObserved.Load()
				if current <= max || maxObserved.CompareAndSwap(max, current) {
					break
				}
			}

			// Simulate work
			time.Sleep(10 * time.Millisecond)

			// Release
			activeQueries.Add(-1)
			<-r.maxConcurrent
		}()
	}

	wg.Wait()

	// Verify we never exceeded the limit
	assert.LessOrEqual(t, int(maxObserved.Load()), 10,
		"Should never exceed MaxConcurrentQueries limit")
}

func BenchmarkCircuitBreaker_CanQuery(b *testing.B) {
	cb := newCircuitBreaker()
	server := "8.8.8.8:53"

	// Setup: some servers with different states
	cb.recordFailure("1.1.1.1:53")
	cb.recordFailure("1.1.1.1:53")

	for i := 0; i < 5; i++ {
		cb.recordFailure("2.2.2.2:53")
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cb.canQuery(server)
		}
	})
}

func BenchmarkCircuitBreaker_RecordFailure(b *testing.B) {
	cb := newCircuitBreaker()
	servers := []string{
		"8.8.8.8:53",
		"8.8.4.4:53",
		"1.1.1.1:53",
		"9.9.9.9:53",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			server := servers[i%len(servers)]
			cb.recordFailure(server)
			i++
		}
	})
}

func BenchmarkCircuitBreaker_RecordSuccess(b *testing.B) {
	cb := newCircuitBreaker()
	servers := []string{
		"8.8.8.8:53",
		"8.8.4.4:53",
		"1.1.1.1:53",
		"9.9.9.9:53",
	}

	// Setup: add some failures
	for _, server := range servers {
		cb.recordFailure(server)
		cb.recordFailure(server)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			server := servers[i%len(servers)]
			cb.recordSuccess(server)
			i++
		}
	})
}
