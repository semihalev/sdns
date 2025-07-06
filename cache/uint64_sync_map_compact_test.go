package cache

import (
	"runtime"
	"testing"
	"time"
)

func TestSyncUInt64MapWithCompaction(t *testing.T) {
	m := NewSyncUInt64Map[string](10)

	runtime.GC()
	runtime.GC()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	initialAlloc := m1.Alloc

	// Add and delete entries repeatedly
	iterations := 10000
	for i := 0; i < iterations; i++ {
		m.Set(uint64(i), "test value")
		m.Del(uint64(i))
	}

	// Before compaction
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	beforeCompact := int64(m2.Alloc) - int64(initialAlloc)

	// With the new implementation, we can't directly count deleted entries
	// but we can check the map size
	mapSize := m.Len()

	// Run compaction (no-op in new implementation)
	_ = m.Compact()

	// After compaction
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	afterCompact := int64(m3.Alloc) - int64(initialAlloc)

	// After compaction, size should still be 0
	mapSizeAfter := m.Len()

	t.Logf("Iterations: %d", iterations)
	t.Logf("Map size: %d", mapSize)
	t.Logf("Map size after compact: %d", mapSizeAfter)
	t.Logf("Memory before compact: %+.2f MB", float64(beforeCompact)/(1024*1024))
	t.Logf("Memory after compact: %+.2f MB", float64(afterCompact)/(1024*1024))

	// The new implementation doesn't have a compaction mechanism
	// as it uses backward shift deletion which maintains compactness
	if mapSize != 0 {
		t.Errorf("Expected map size to be 0 after deleting all entries, got %d", mapSize)
	}

	if mapSizeAfter != 0 {
		t.Errorf("Expected map size to remain 0 after compact, got %d", mapSizeAfter)
	}
}

func TestCacheWithAutomaticCompaction(t *testing.T) {
	cache := New(10000)
	defer cache.Stop()

	runtime.GC()
	runtime.GC()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	initialAlloc := m1.Alloc

	// Simulate cache churn
	for cycle := 0; cycle < 10; cycle++ {
		// Add 1000 entries
		for i := 0; i < 1000; i++ {
			cache.Add(uint64(cycle*1000+i), "cache entry data")
		}

		// Remove them all
		for i := 0; i < 1000; i++ {
			cache.Remove(uint64(cycle*1000 + i))
		}

		runtime.GC()
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)

		allocDiff := int64(m2.Alloc) - int64(initialAlloc)
		t.Logf("Cycle %d: Memory %+.2f MB, Cache len=%d",
			cycle+1, float64(allocDiff)/(1024*1024), cache.Len())
	}

	// Force a compaction
	cleaned := cache.data.Compact()

	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var mFinal runtime.MemStats
	runtime.ReadMemStats(&mFinal)
	finalAllocDiff := int64(mFinal.Alloc) - int64(initialAlloc)

	t.Logf("\nAfter manual compaction:")
	t.Logf("  Cleaned %d nodes", cleaned)
	t.Logf("  Final memory: %+.2f MB", float64(finalAllocDiff)/(1024*1024))

	// Memory should be minimal after compaction
	if finalAllocDiff > 1024*1024 { // 1MB threshold
		t.Errorf("Memory usage after compaction too high: %.2f MB", float64(finalAllocDiff)/(1024*1024))
	}
}
