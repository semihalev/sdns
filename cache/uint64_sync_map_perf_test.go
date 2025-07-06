package cache

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// BenchmarkCacheWithHighChurn tests performance under high churn conditions
func BenchmarkCacheWithHighChurn(b *testing.B) {
	cache := New(500000) // SDNS default size
	defer cache.Stop()

	b.Run("HighChurn", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := uint64(i)
			cache.Add(key, "test value")
			cache.Remove(key)
		}
	})

	// Force compaction
	cache.data.Compact()

	b.Run("AfterCompact", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := uint64(i % 1000) // Reuse keys
			cache.Add(key, "test value")
			_, _ = cache.Get(key)
		}
	})
}

func TestHighChurnMemoryLeak(t *testing.T) {
	m := NewSyncUInt64Map[string](10)

	runtime.GC()
	runtime.GC()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	initialAlloc := m1.Alloc

	// Create high churn
	for i := 0; i < 100000; i++ {
		m.Set(uint64(i), "test value")
		m.Del(uint64(i))
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	afterChurn := int64(m2.Alloc) - int64(initialAlloc)

	t.Logf("After churn:")
	t.Logf("  Memory usage: %+.2f MB", float64(afterChurn)/(1024*1024))
	t.Logf("  Map len: %d", m.Len())

	// Compact
	cleaned := m.Compact()

	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	afterCompact := int64(m3.Alloc) - int64(initialAlloc)

	t.Logf("After compact:")
	t.Logf("  Cleaned: %d entries", cleaned)
	t.Logf("  Memory usage: %+.2f MB", float64(afterCompact)/(1024*1024))

	if afterChurn > 0 && afterCompact > 0 {
		t.Logf("  Memory reduction: %.1f%%", float64(afterChurn-afterCompact)/float64(afterChurn)*100)
	}
}

// BenchmarkMapOperations benchmarks individual operations
func BenchmarkMapOperations(b *testing.B) {
	sizes := []int{1000, 10000, 100000, 500000}

	for _, size := range sizes {
		m := NewSyncUInt64Map[string](18) // 2^18 = 262k buckets

		// Pre-populate
		for i := 0; i < size; i++ {
			m.Set(uint64(i), "test-value")
		}

		b.Run(fmt.Sprintf("Get-%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = m.Get(uint64(i % size))
			}
		})

		b.Run(fmt.Sprintf("Set-%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.Set(uint64(size+i), "new-value")
			}
		})

		b.Run(fmt.Sprintf("Del-%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.Del(uint64(i % size))
			}
		})
	}
}

// BenchmarkConcurrentAccess benchmarks concurrent operations
func BenchmarkConcurrentAccess(b *testing.B) {
	m := NewSyncUInt64Map[string](18)

	// Pre-populate
	for i := 0; i < 100000; i++ {
		m.Set(uint64(i), "test-value")
	}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := uint64(i % 100000)
			switch i % 3 {
			case 0:
				m.Get(key)
			case 1:
				m.Set(key, "updated-value")
			case 2:
				m.Del(key)
			}
			i++
		}
	})
}

// TestCompactionEffectiveness tests how well compaction recovers memory
func TestCompactionEffectiveness(t *testing.T) {
	m := NewSyncUInt64Map[string](12) // 4096 buckets

	// Phase 1: Fill the map
	for i := 0; i < 10000; i++ {
		m.Set(uint64(i), "test-value")
	}

	initialSize := m.Len()
	t.Logf("Initial size: %d", initialSize)

	// Phase 2: Delete 90% of entries
	for i := 0; i < 9000; i++ {
		m.Del(uint64(i))
	}

	afterDeleteSize := m.Len()
	t.Logf("After deleting 90%%: size=%d", afterDeleteSize)

	// Phase 3: Compact (no-op in new implementation)
	cleaned := m.Compact()
	t.Logf("Compaction cleaned: %d entries", cleaned)

	// Phase 4: Add new entries - should be fast
	start := time.Now()
	for i := 10000; i < 11000; i++ {
		m.Set(uint64(i), "new-value")
	}
	elapsed := time.Since(start)
	t.Logf("Time to add 1000 entries after deletions: %v", elapsed)

	finalSize := m.Len()
	t.Logf("Final size: %d", finalSize)
}

// TestConcurrentChurn tests the map under concurrent high-churn conditions
func TestConcurrentChurn(t *testing.T) {
	m := NewSyncUInt64Map[string](14) // 16k buckets
	numGoroutines := 10
	opsPerGoroutine := 10000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	start := time.Now()

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()

			base := uint64(goroutineID * opsPerGoroutine)
			for i := 0; i < opsPerGoroutine; i++ {
				key := base + uint64(i)

				// Add
				m.Set(key, "test-value")

				// Sometimes read
				if i%10 == 0 {
					_, _ = m.Get(key)
				}

				// Delete
				if i%2 == 0 {
					m.Del(key)
				}
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)

	finalSize := m.Len()
	t.Logf("Concurrent churn completed in %v", elapsed)
	t.Logf("Final map size: %d", finalSize)
	t.Logf("Operations per second: %.0f", float64(numGoroutines*opsPerGoroutine*3)/elapsed.Seconds())

	// Compact and measure
	compactStart := time.Now()
	cleaned := m.Compact()
	compactElapsed := time.Since(compactStart)

	t.Logf("Compaction cleaned %d entries in %v", cleaned, compactElapsed)
}
