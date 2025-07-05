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
	beforeCompact := m2.Alloc - initialAlloc

	// Count nodes before compaction
	totalNodesBefore := 0
	deletedNodesBefore := 0
	for i := range m.buckets {
		node := (*fnode[string])(m.buckets[i].head)
		for node != nil {
			totalNodesBefore++
			if node.deleted == 1 {
				deletedNodesBefore++
			}
			node = (*fnode[string])(node.next)
		}
	}

	// Run compaction
	cleaned := m.Compact()

	// After compaction
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	afterCompact := m3.Alloc - initialAlloc

	// Count nodes after compaction
	totalNodesAfter := 0
	deletedNodesAfter := 0
	for i := range m.buckets {
		node := (*fnode[string])(m.buckets[i].head)
		for node != nil {
			totalNodesAfter++
			if node.deleted == 1 {
				deletedNodesAfter++
			}
			node = (*fnode[string])(node.next)
		}
	}

	t.Logf("Before compaction:")
	t.Logf("  Memory: %.2f MB", float64(beforeCompact)/(1024*1024))
	t.Logf("  Total nodes: %d", totalNodesBefore)
	t.Logf("  Deleted nodes: %d", deletedNodesBefore)

	t.Logf("\nAfter compaction:")
	t.Logf("  Memory: %.2f MB", float64(afterCompact)/(1024*1024))
	t.Logf("  Total nodes: %d", totalNodesAfter)
	t.Logf("  Deleted nodes: %d", deletedNodesAfter)
	t.Logf("  Nodes cleaned: %d", cleaned)

	// Verify compaction worked
	if totalNodesAfter != 0 {
		t.Errorf("Expected 0 nodes after compaction, got %d", totalNodesAfter)
	}

	if cleaned != iterations {
		t.Errorf("Expected to clean %d nodes, cleaned %d", iterations, cleaned)
	}
}

func TestCacheWithAutomaticCompaction(t *testing.T) {
	// Create cache with automatic compaction
	cache := New(1000)
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

		allocDiff := m2.Alloc - initialAlloc
		t.Logf("Cycle %d: Memory +%.2f MB, Cache len=%d",
			cycle+1, float64(allocDiff)/(1024*1024), cache.Len())
	}

	// Force a compaction
	cleaned := cache.data.Compact()

	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var mFinal runtime.MemStats
	runtime.ReadMemStats(&mFinal)
	finalAllocDiff := mFinal.Alloc - initialAlloc

	t.Logf("\nAfter manual compaction:")
	t.Logf("  Cleaned %d nodes", cleaned)
	t.Logf("  Final memory: +%.2f MB", float64(finalAllocDiff)/(1024*1024))

	// Memory should be minimal after compaction
	if finalAllocDiff > 1024*1024 { // 1MB threshold
		t.Errorf("Memory usage after compaction too high: %.2f MB", float64(finalAllocDiff)/(1024*1024))
	}
}
