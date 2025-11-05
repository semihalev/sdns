package cache

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"
)

// BenchmarkCachePerformance benchmarks the new cache implementation.
func BenchmarkCachePerformance(b *testing.B) {
	sizes := []int{10000, 100000, 256000, 500000}
	readRatios := []float64{0.95, 0.90, 0.80} // DNS caches are read-heavy

	for _, size := range sizes {
		for _, readRatio := range readRatios {
			name := fmt.Sprintf("Size_%d_ReadRatio_%.0f", size, readRatio*100)

			b.Run("Cache_"+name, func(b *testing.B) {
				benchmarkCachePerf(b, size, readRatio)
			})
		}
	}
}

func benchmarkCachePerf(b *testing.B, size int, readRatio float64) {
	c := New(size)
	keys := generateTestKeys(size)

	// Pre-populate 50%
	for i := 0; i < size/2; i++ {
		c.Add(keys[i], i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // G404 - benchmark test
		for pb.Next() {
			key := keys[rng.Intn(size)] //nolint:gosec // G115 - bounded by size
			r := rng.Float64()

			switch {
			case r < readRatio:
				c.Get(key)
			case r < readRatio+(1-readRatio)/2:
				c.Add(key, key)
			default:
				c.Remove(key)
			}
		}
	})
}

func generateTestKeys(n int) []uint64 {
	keys := make([]uint64, n)
	for i := 0; i < n; i++ {
		// Simulate DNS cache keys (spread out)
		keys[i] = uint64(i) * 0x9E3779B9 //nolint:gosec // G115 - test key generation
	}
	return keys
}

// BenchmarkHighConcurrency tests under extreme concurrency (simulating busy DNS server).
func BenchmarkHighConcurrency(b *testing.B) {
	const size = 256000 // Standard SDNS cache size
	numCPU := runtime.NumCPU()
	concurrencies := []int{numCPU, numCPU * 2, numCPU * 4}

	for _, concurrency := range concurrencies {
		b.Run(fmt.Sprintf("Cache_Concurrent_%d", concurrency), func(b *testing.B) {
			c := New(size)
			benchmarkConcurrent(b, c, concurrency)
		})
	}
}

type cacheOps interface {
	Get(uint64) (any, bool)
	Add(uint64, any)
	Remove(uint64)
	Len() int
}

func benchmarkConcurrent(b *testing.B, c cacheOps, numGoroutines int) {
	keys := generateTestKeys(256000)

	// Pre-populate
	for i := 0; i < 128000; i++ {
		c.Add(keys[i], i)
	}

	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	opsPerGoroutine := b.N / numGoroutines

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id))) //nolint:gosec // G404 - test random

			for j := 0; j < opsPerGoroutine; j++ {
				key := keys[rng.Intn(len(keys))]

				switch rng.Intn(100) {
				case 0, 1, 2, 3, 4: // 5% deletes
					c.Remove(key)
				case 5, 6, 7, 8, 9, 10, 11, 12, 13, 14: // 10% writes
					c.Add(key, j)
				default: // 85% reads (typical DNS cache pattern)
					c.Get(key)
				}
			}
		}(i)
	}

	wg.Wait()
	b.StopTimer()

	elapsed := time.Since(start)
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "ops/s")
	b.ReportMetric(float64(numGoroutines), "goroutines")
}
