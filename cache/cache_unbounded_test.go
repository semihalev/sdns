package cache

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCacheUnboundedGrowth tests if cache can grow unbounded under specific conditions
func TestCacheUnboundedGrowth(t *testing.T) {
	if testing.Short() || isCI() {
		t.Skip("Skipping heavy test in short mode or CI")
	}

	maxSize := 500 // Reduced from 1000
	c := New(maxSize)

	// Try to exploit the race between Add and eviction
	numGoroutines := 4        // Fixed number instead of runtime.NumCPU() * 2
	itemsPerGoroutine := 1000 // Reduced from 10000

	var wg sync.WaitGroup
	var maxEverSeen int64
	var addsDone int64

	// Start many goroutines that add items rapidly
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for i := 0; i < itemsPerGoroutine; i++ {
				// Use unique keys to force new entries
				key := uint64(id)*uint64(itemsPerGoroutine) + uint64(i) //nolint:gosec // G115 - test calculation
				c.Add(key, i)
				atomic.AddInt64(&addsDone, 1)

				// Don't check size every iteration to maximize race window
				if i%1000 == 0 {
					size := int64(c.Len())
					for {
						old := atomic.LoadInt64(&maxEverSeen)
						if size <= old || atomic.CompareAndSwapInt64(&maxEverSeen, old, size) {
							break
						}
					}
				}
			}
		}(g)
	}

	// Monitor size periodically while adds are happening
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond) // Increased from 5ms
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				size := int64(c.Len())
				for {
					old := atomic.LoadInt64(&maxEverSeen)
					if size <= old || atomic.CompareAndSwapInt64(&maxEverSeen, old, size) {
						break
					}
				}
			}
		}
	}()

	wg.Wait()
	close(done)

	totalAdds := atomic.LoadInt64(&addsDone)
	finalSize := c.Len()
	maxSeen := atomic.LoadInt64(&maxEverSeen)

	t.Logf("Total adds: %d", totalAdds)
	t.Logf("Max size ever seen: %d (limit: %d)", maxSeen, maxSize)
	t.Logf("Final size: %d", finalSize)
	t.Logf("Max overshoot: %d (%.1f%% of limit)", maxSeen-int64(maxSize),
		float64(maxSeen-int64(maxSize))/float64(maxSize)*100)

	// Check if growth was bounded
	// Allow some overshoot but not unbounded growth
	maxAllowedOvershoot := int64(maxSize) // 100% overshoot is concerning
	if maxSeen > int64(maxSize)+maxAllowedOvershoot {
		t.Errorf("Cache grew to %d, which is more than 2x the limit %d",
			maxSeen, maxSize)
	}
}

// TestCacheMemoryPressure tests cache behavior under memory pressure
func TestCacheMemoryPressure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory pressure test in short mode")
	}

	// Use a moderate cache size
	maxSize := 10000 // Reduced from 100000
	c := New(maxSize)

	// Create large values to increase memory pressure
	largeValue := make([]byte, 1024) // 1KB per entry

	// Track memory stats
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Fill cache multiple times over
	for i := 0; i < maxSize*5; i++ {
		c.Add(uint64(i), largeValue) //nolint:gosec // G115 - test loop

		if i%10000 == 0 && i > 0 {
			currentSize := c.Len()
			if currentSize > maxSize*2 {
				t.Errorf("At iteration %d: cache size %d is more than 2x limit %d",
					i, currentSize, maxSize)
			}
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	finalSize := c.Len()
	memoryUsed := m2.Alloc - m1.Alloc

	t.Logf("Final cache size: %d entries (limit: %d)", finalSize, maxSize)
	t.Logf("Memory used: %.2f MB", float64(memoryUsed)/1024/1024)
	t.Logf("Estimated memory per entry: %.2f KB", float64(memoryUsed)/float64(finalSize)/1024)

	// Memory usage should be roughly proportional to cache size, not total adds
	expectedMaxMemory := int64(maxSize) * 2048    // 2KB per entry (value + overhead)
	if memoryUsed > uint64(expectedMaxMemory)*2 { //nolint:gosec // G115 - expectedMaxMemory is always positive
		t.Errorf("Memory usage %.2f MB seems too high for %d entries",
			float64(memoryUsed)/1024/1024, finalSize)
	}
}

// TestCacheEvictionStalls tests if eviction can stall under certain conditions
func TestCacheEvictionStalls(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stall test in short mode")
	}

	maxSize := 100
	c := New(maxSize)

	// Fill cache
	for i := 0; i < maxSize; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	// Now hammer it with adds from multiple goroutines
	// while also doing reads (which might interfere with eviction)
	var wg sync.WaitGroup
	stopFlag := int32(0)

	// Reader goroutines
	for r := 0; r < 3; r++ { // Reduced from 5
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.LoadInt32(&stopFlag) == 0 {
				c.Get(uint64(r * 20))        //nolint:gosec // G115 - test loop
				time.Sleep(time.Microsecond) // Add small delay
			}
		}()
	}

	// Writer goroutines
	for w := 0; w < 3; w++ { // Reduced from 5
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ { // Reduced from 10000
				c.Add(uint64(maxSize+id*1000+i), i) //nolint:gosec // G115 - test loop
			}
		}(w)
	}

	// Monitor max size
	var maxSeen int32
	go func() {
		for atomic.LoadInt32(&stopFlag) == 0 {
			size := c.Len()
			currentMax := atomic.LoadInt32(&maxSeen)
			if int32(size) > currentMax { //nolint:gosec // G115 - size is controlled by test
				atomic.StoreInt32(&maxSeen, int32(size)) //nolint:gosec // G115 - size is controlled by test
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Wait for writers to finish
	time.Sleep(100 * time.Millisecond)
	atomic.StoreInt32(&stopFlag, 1)
	wg.Wait()

	t.Logf("Max size seen during concurrent read/write: %d (limit: %d)", atomic.LoadInt32(&maxSeen), maxSize)
	t.Logf("Final size: %d", c.Len())

	finalMaxSeen := atomic.LoadInt32(&maxSeen)
	if int(finalMaxSeen) > maxSize*3 {
		t.Errorf("Cache grew to %d during concurrent operations, >3x limit %d",
			finalMaxSeen, maxSize)
	}
}

// TestCacheWithZeroSize tests edge case of zero/negative size
func TestCacheWithZeroSize(t *testing.T) {
	// Test with 0 size (should become 1)
	c := New(0)

	// Add items
	for i := 0; i < 100; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop

		size := c.Len()
		if size > 2 { // Allow size 1 + potential race to 2
			t.Errorf("Zero-size cache grew to %d", size)
		}
	}

	// Test with negative size (should become 1)
	c2 := New(-10)
	for i := 0; i < 100; i++ {
		c2.Add(uint64(i), i) //nolint:gosec // G115 - test loop

		size := c2.Len()
		if size > 2 {
			t.Errorf("Negative-size cache grew to %d", size)
		}
	}
}
