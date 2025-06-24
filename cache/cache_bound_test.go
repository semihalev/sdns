package cache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCacheBoundStrict tests that cache never exceeds max size by more than eviction batch size
func TestCacheBoundStrict(t *testing.T) {
	maxSize := 1000
	c := New(maxSize)

	// Track max observed size
	var maxObserved int64

	// Add items continuously and check size
	for i := 0; i < maxSize*10; i++ {
		c.Add(uint64(i), i)

		currentSize := int64(c.Len())
		for {
			old := atomic.LoadInt64(&maxObserved)
			if currentSize <= old || atomic.CompareAndSwapInt64(&maxObserved, old, currentSize) {
				break
			}
		}

		// Check bound - allow for one eviction batch overhead
		evictionBatch := maxSize / 20 // 5% as per eviction logic
		if evictionBatch < 1 {
			evictionBatch = 1
		}

		if currentSize > int64(maxSize+evictionBatch) {
			t.Fatalf("Cache size %d exceeds max size %d by more than eviction batch %d",
				currentSize, maxSize, evictionBatch)
		}
	}

	t.Logf("Max observed size: %d (max allowed: %d)", maxObserved, maxSize)
}

// TestCacheBoundUnderHeavyConcurrency tests cache bounds under extreme concurrent load
func TestCacheBoundUnderHeavyConcurrency(t *testing.T) {
	maxSize := 10000
	c := New(maxSize)

	numGoroutines := 100
	itemsPerGoroutine := 10000

	var wg sync.WaitGroup
	var maxObserved int64
	stopMonitor := make(chan bool)

	// Monitor goroutine to track size continuously
	go func() {
		ticker := time.NewTicker(1 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				currentSize := int64(c.Len())
				for {
					old := atomic.LoadInt64(&maxObserved)
					if currentSize <= old || atomic.CompareAndSwapInt64(&maxObserved, old, currentSize) {
						break
					}
				}
			case <-stopMonitor:
				return
			}
		}
	}()

	// Launch concurrent writers
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for i := 0; i < itemsPerGoroutine; i++ {
				key := uint64(goroutineID*itemsPerGoroutine + i)
				c.Add(key, fmt.Sprintf("value-%d-%d", goroutineID, i))

				// Occasionally check size
				if i%100 == 0 {
					currentSize := c.Len()
					// Allow 20% overhead during concurrent operations
					if currentSize > maxSize+maxSize/5 {
						t.Errorf("During concurrent ops: cache size %d exceeds max %d by >20%%",
							currentSize, maxSize)
					}
				}
			}
		}(g)
	}

	wg.Wait()
	close(stopMonitor)

	// Final check after all operations complete
	finalSize := c.Len()
	t.Logf("Final size: %d, Max observed: %d (max allowed: %d)",
		finalSize, maxObserved, maxSize)

	// After operations complete, cache should stabilize near max size
	if finalSize > maxSize+maxSize/20 { // Allow 5% tolerance
		t.Errorf("Final cache size %d exceeds max size %d by more than 5%%",
			finalSize, maxSize)
	}
}

// TestCacheEvictionEffectiveness tests that eviction actually removes items
func TestCacheEvictionEffectiveness(t *testing.T) {
	maxSize := 100
	c := New(maxSize)

	// Fill cache completely
	for i := 0; i < maxSize; i++ {
		c.Add(uint64(i), i)
	}

	initialSize := c.Len()
	if initialSize != maxSize {
		t.Fatalf("Initial size %d != max size %d", initialSize, maxSize)
	}

	// Add more items to trigger eviction
	for i := maxSize; i < maxSize*2; i++ {
		c.Add(uint64(i), i)
	}

	// Count how many of the original items remain
	originalRemaining := 0
	for i := 0; i < maxSize; i++ {
		if _, found := c.Get(uint64(i)); found {
			originalRemaining++
		}
	}

	// Count how many new items were added
	newItems := 0
	for i := maxSize; i < maxSize*2; i++ {
		if _, found := c.Get(uint64(i)); found {
			newItems++
		}
	}

	t.Logf("Original items remaining: %d/%d", originalRemaining, maxSize)
	t.Logf("New items added: %d/%d", newItems, maxSize)
	t.Logf("Total items: %d (max: %d)", c.Len(), maxSize)

	// Verify that eviction actually happened
	if originalRemaining == maxSize {
		t.Error("No original items were evicted")
	}

	if newItems == 0 {
		t.Error("No new items were added")
	}
}

// TestCacheSizeMonitoring monitors cache size over time with continuous additions
func TestCacheSizeMonitoring(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}

	maxSize := 50000
	c := New(maxSize)

	// Record size over time
	sizeHistory := make([]int, 0, 1000)
	var mu sync.Mutex

	// Monitor size in background
	stopMonitor := make(chan bool)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				size := c.Len()
				mu.Lock()
				sizeHistory = append(sizeHistory, size)
				mu.Unlock()
			case <-stopMonitor:
				return
			}
		}
	}()

	// Add items continuously for 2 seconds
	start := time.Now()
	i := 0
	for time.Since(start) < 2*time.Second {
		c.Add(uint64(i), i)
		i++

		// Add some reads to simulate real usage
		if i%10 == 0 {
			c.Get(uint64(i / 2))
		}
	}

	close(stopMonitor)
	time.Sleep(50 * time.Millisecond) // Let monitor capture final state

	// Analyze size history
	mu.Lock()
	defer mu.Unlock()

	maxObserved := 0
	exceedances := 0
	for _, size := range sizeHistory {
		if size > maxObserved {
			maxObserved = size
		}
		if size > maxSize {
			exceedances++
		}
	}

	exceedanceRate := float64(exceedances) / float64(len(sizeHistory)) * 100

	t.Logf("Items added: %d", i)
	t.Logf("Size samples: %d", len(sizeHistory))
	t.Logf("Max observed size: %d (limit: %d)", maxObserved, maxSize)
	t.Logf("Times exceeded limit: %d (%.2f%%)", exceedances, exceedanceRate)

	// The cache may temporarily exceed the limit but should quickly recover
	if exceedanceRate > 10 {
		t.Errorf("Cache exceeded limit too often: %.2f%% of samples", exceedanceRate)
	}

	// Max observed should not be too far above limit
	if maxObserved > maxSize+maxSize/10 {
		t.Errorf("Max observed size %d exceeds limit %d by more than 10%%",
			maxObserved, maxSize)
	}
}

// TestCacheEvictionDeadlock tests that eviction doesn't cause deadlock
func TestCacheEvictionDeadlock(t *testing.T) {
	maxSize := 100
	c := New(maxSize)

	// Use timeout to detect deadlock
	done := make(chan bool)
	go func() {
		// Continuously add items
		for i := 0; i < 10000; i++ {
			c.Add(uint64(i), i)
		}
		done <- true
	}()

	select {
	case <-done:
		// Success - no deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("Possible deadlock detected - operations took too long")
	}
}

// TestCacheEvictionWithLargeItems simulates cache with varying item sizes
func TestCacheEvictionWithLargeItems(t *testing.T) {
	maxSize := 1000
	c := New(maxSize)

	// Add items of varying "sizes" (simulated by value content)
	for i := 0; i < maxSize*5; i++ {
		// Create values of different sizes
		size := (i % 100) + 1
		value := make([]byte, size*100) // Simulate different memory usage
		c.Add(uint64(i), value)

		if i%100 == 0 {
			currentSize := c.Len()
			if currentSize > maxSize+maxSize/10 {
				t.Errorf("Cache size %d exceeds max %d by >10%% with varied items",
					currentSize, maxSize)
			}
		}
	}

	finalSize := c.Len()
	t.Logf("Final size with varied items: %d (max: %d)", finalSize, maxSize)
}

// BenchmarkCacheBoundChecking benchmarks overhead of bound checking
func BenchmarkCacheBoundChecking(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			c := New(size)

			// Pre-fill to 80% capacity
			for i := 0; i < size*8/10; i++ {
				c.Add(uint64(i), i)
			}

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					// This will trigger eviction checking
					c.Add(uint64(i), i)
					i++
				}
			})
		})
	}
}
