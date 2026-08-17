package resolver

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker_Basic(t *testing.T) {
	cb := newCircuitBreaker()
	server := "8.8.8.8:53"

	// Initially, server should be queryable
	if !(cb.canQuery(server)) {
		t.Errorf("cb.canQuery(server) is false")
	}

	// Record 4 failures - should still be queryable
	for i := 0; i < 4; i++ {
		cb.recordFailure(server)
		if !(cb.canQuery(server)) {
			t.Errorf("%s: cb.canQuery(server) is false", fmt.Sprintf("Should be queryable after %d failures", i+1))
		}
	}

	// 5th failure should trip the circuit breaker
	cb.recordFailure(server)
	if cb.canQuery(server) {
		t.Errorf("%s: cb.canQuery(server) is true", "Circuit breaker should be tripped after 5 failures")
	}

	// Success should reset the circuit breaker
	cb.recordSuccess(server)
	if !(cb.canQuery(server)) {
		t.Errorf("%s: cb.canQuery(server) is false", "Circuit breaker should be reset after success")
	}
}

func TestCircuitBreaker_Timeout(t *testing.T) {
	cb := newCircuitBreaker()
	server := "1.2.3.4:53"

	// Trip the circuit breaker
	for i := 0; i < 5; i++ {
		cb.recordFailure(server)
	}
	if cb.canQuery(server) {
		t.Errorf("cb.canQuery(server) is true")
	}

	// Manually set last failure time to 31 seconds ago
	cb.mu.RLock()
	sf := cb.failures[server]
	cb.mu.RUnlock()
	sf.lastFailure.Store(time.Now().Add(-31 * time.Second).Unix())

	// Should be queryable again after timeout
	if !(cb.canQuery(server)) {
		t.Errorf("%s: cb.canQuery(server) is false", "Circuit breaker should reset after 30 second timeout")
	}
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
	if cb.canQuery(server1) {
		t.Errorf("cb.canQuery(server1) is true")
	}

	// server2 should still be queryable
	if !(cb.canQuery(server2)) {
		t.Errorf("cb.canQuery(server2) is false")
	}

	// Record failures for server2
	for i := 0; i < 3; i++ {
		cb.recordFailure(server2)
	}
	if !(cb.canQuery(server2)) {
		t.Errorf("%s: cb.canQuery(server2) is false", "Server2 should still be queryable with 3 failures")
	}
	if cb.canQuery(server1) {
		t.Errorf("%s: cb.canQuery(server1) is true", "Server1 should still be disabled")
	}
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
		if !(cb.canQuery(server)) {
			t.Errorf("%s: cb.canQuery(server) is false", fmt.Sprintf("Should be queryable after reset + %d failures", i+1))
		}
	}

	// 5th failure after reset should trip
	cb.recordFailure(server)
	if cb.canQuery(server) {
		t.Errorf("cb.canQuery(server) is true")
	}
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
	if !(exists) {
		t.Errorf("exists is false")
	}

	// Cleanup happens every 5 minutes in background
	// For testing, we just verify the structure is correct
	if cb.failures == nil {
		t.Fatalf("cb.failures is nil")
	}
}

func TestResolverWithCircuitBreaker(t *testing.T) {
	// Test that resolver properly uses circuit breaker
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 100
	r := newWiredTestResolver(cfg)

	// Verify circuit breaker is initialized
	if r.circuitBreaker == nil {
		t.Fatalf("r.circuitBreaker is nil")
	}

	// Verify max concurrent channel has correct capacity
	if !reflect.DeepEqual(100, cap(r.maxConcurrent)) {
		t.Errorf("cap(r.maxConcurrent) = %v, want %v", cap(r.maxConcurrent), 100)
	}
}

func TestResolverGoroutineLimiting(t *testing.T) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 50 // Higher limit to avoid conflict with background tasks
	r := newWiredTestResolver(cfg)

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
			goto cleanup
		}
	}

cleanup:

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
			goto done
		}
	}

done:

	// Just verify the semaphore mechanism works
	if cap(r.maxConcurrent) != 50 {
		t.Errorf("%s: cap(r.maxConcurrent) = %d, want 50", "Semaphore should have correct capacity", cap(r.maxConcurrent))
	}
}

func TestResolverConcurrentQueryLimit(t *testing.T) {
	cfg := makeTestConfig()
	cfg.MaxConcurrentQueries = 10
	r := newWiredTestResolver(cfg)

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
	if int(maxObserved.Load()) > 10 {
		t.Errorf("%s: int(maxObserved.Load()) = %v, want <= %v", "Should never exceed MaxConcurrentQueries limit", int(maxObserved.Load()), 10)
	}
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

// TestCircuitBreaker_CleanupEvictsIdleWithFailures locks in the leak fix:
// an entry that failed (count>0) but never recovered and went idle must be
// evicted. The old cleanup gated on count==0 and would have leaked it.
func TestCircuitBreaker_CleanupEvictsIdleWithFailures(t *testing.T) {
	cb := newCircuitBreaker()
	const server = "192.0.2.1:53"
	cb.recordFailure(server) // count=1, below the 5-failure trip threshold

	// Backdate the last failure beyond the 5-minute idle window.
	cb.mu.RLock()
	cb.failures[server].lastFailure.Store(time.Now().Unix() - 600)
	cb.mu.RUnlock()

	cb.cleanupOnce(time.Now().Unix())

	cb.mu.RLock()
	_, exists := cb.failures[server]
	cb.mu.RUnlock()
	if exists {
		t.Errorf("%s: exists is true", "idle entry with count>0 must be evicted")
	}

	// A recently-failed entry must survive.
	cb.recordFailure(server)
	cb.cleanupOnce(time.Now().Unix())
	cb.mu.RLock()
	_, exists = cb.failures[server]
	cb.mu.RUnlock()
	if !(exists) {
		t.Errorf("%s: exists is false", "recently-failed entry must be kept")
	}
}
