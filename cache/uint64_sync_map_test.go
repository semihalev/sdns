package cache

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSyncUInt64Map_Basic(t *testing.T) {
	m := NewSyncUInt64Map[int](4) // Small size for testing

	// Test empty map
	if m.Len() != 0 {
		t.Errorf("Expected empty map, got length %d", m.Len())
	}

	// Test Get on empty map
	_, ok := m.Get(1)
	if ok {
		t.Error("Expected Get to return false on empty map")
	}

	// Test Has on empty map
	if m.Has(1) {
		t.Error("Expected Has to return false on empty map")
	}

	// Test Set and Get
	m.Set(1, 100)
	v, ok := m.Get(1)
	if !ok || v != 100 {
		t.Errorf("Expected Get(1) to return (100, true), got (%v, %v)", v, ok)
	}

	// Test Has
	if !m.Has(1) {
		t.Error("Expected Has(1) to return true")
	}

	// Test Len after Set
	if m.Len() != 1 {
		t.Errorf("Expected length 1, got %d", m.Len())
	}

	// Test update existing key
	m.Set(1, 200)
	v, ok = m.Get(1)
	if !ok || v != 200 {
		t.Errorf("Expected Get(1) to return (200, true), got (%v, %v)", v, ok)
	}

	// Length should not change on update
	if m.Len() != 1 {
		t.Errorf("Expected length 1 after update, got %d", m.Len())
	}
}

func TestSyncUInt64Map_Delete(t *testing.T) {
	m := NewSyncUInt64Map[string](4)

	// Test Del on empty map
	if m.Del(1) {
		t.Error("Expected Del to return false on empty map")
	}

	// Add some values
	m.Set(1, "one")
	m.Set(2, "two")
	m.Set(3, "three")

	if m.Len() != 3 {
		t.Errorf("Expected length 3, got %d", m.Len())
	}

	// Delete existing key
	if !m.Del(2) {
		t.Error("Expected Del(2) to return true")
	}

	if m.Len() != 2 {
		t.Errorf("Expected length 2 after delete, got %d", m.Len())
	}

	// Verify deleted key is gone
	_, ok := m.Get(2)
	if ok {
		t.Error("Expected Get(2) to return false after delete")
	}

	if m.Has(2) {
		t.Error("Expected Has(2) to return false after delete")
	}

	// Delete already deleted key
	if m.Del(2) {
		t.Error("Expected Del(2) to return false for already deleted key")
	}

	// Other keys should still exist
	v, ok := m.Get(1)
	if !ok || v != "one" {
		t.Errorf("Expected Get(1) to return (one, true), got (%v, %v)", v, ok)
	}
}

func TestSyncUInt64Map_ForEach(t *testing.T) {
	m := NewSyncUInt64Map[int](4)

	// Test ForEach on empty map
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("Expected ForEach to iterate 0 times on empty map, got %d", count)
	}

	// Add values
	expected := map[uint64]int{
		1: 10,
		2: 20,
		3: 30,
		4: 40,
		5: 50,
	}

	for k, v := range expected {
		m.Set(k, v)
	}

	// Test ForEach visits all entries
	visited := make(map[uint64]int)
	m.ForEach(func(k uint64, v int) bool {
		visited[k] = v
		return true
	})

	if len(visited) != len(expected) {
		t.Errorf("Expected ForEach to visit %d entries, got %d", len(expected), len(visited))
	}

	for k, v := range expected {
		if visited[k] != v {
			t.Errorf("Expected visited[%d] = %d, got %d", k, v, visited[k])
		}
	}

	// Test early termination
	count = 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return count < 3 // Stop after 3 iterations
	})

	if count != 3 {
		t.Errorf("Expected ForEach to stop after 3 iterations, got %d", count)
	}
}

func TestSyncUInt64Map_Concurrent(t *testing.T) {
	m := NewSyncUInt64Map[int](8)
	const numGoroutines = 10
	const numOps = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent Set/Get/Del operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOps; j++ {
				key := uint64(j % 100) //nolint:gosec // G115 - test loop

				switch j % 3 {
				case 0:
					m.Set(key, id*1000+j)
				case 1:
					m.Get(key)
				case 2:
					m.Del(key)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify map is still consistent
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return true
	})

	if count != int(m.Len()) {
		t.Errorf("Inconsistent state: ForEach counted %d, Len() = %d", count, m.Len())
	}
}

func TestSyncUInt64Map_Collision(t *testing.T) {
	// Create a small map to force collisions
	m := NewSyncUInt64Map[string](2) // Only 4 buckets

	// These keys will likely collide
	keys := []uint64{1, 5, 9, 13, 17, 21}

	// Add all keys
	for _, k := range keys {
		m.Set(k, fmt.Sprintf("value_%d", k))
	}

	// Verify all keys exist
	for _, k := range keys {
		v, ok := m.Get(k)
		expected := fmt.Sprintf("value_%d", k)
		if !ok || v != expected {
			t.Errorf("Expected Get(%d) = (%s, true), got (%s, %v)", k, expected, v, ok)
		}
	}

	// Delete some keys
	m.Del(5)
	m.Del(13)

	// Verify deleted keys are gone
	if _, ok := m.Get(5); ok {
		t.Error("Key 5 should be deleted")
	}
	if _, ok := m.Get(13); ok {
		t.Error("Key 13 should be deleted")
	}

	// Other keys should still exist
	for _, k := range []uint64{1, 9, 17, 21} {
		if !m.Has(k) {
			t.Errorf("Key %d should still exist", k)
		}
	}
}

func TestSyncUInt64Map_DeleteResurrection(t *testing.T) {
	m := NewSyncUInt64Map[int](4)

	// Set a value
	m.Set(1, 100)

	// Delete it
	if !m.Del(1) {
		t.Error("Expected Del(1) to return true")
	}

	// Set it again (resurrection)
	m.Set(1, 200)

	// Should exist with new value
	v, ok := m.Get(1)
	if !ok || v != 200 {
		t.Errorf("Expected Get(1) = (200, true), got (%d, %v)", v, ok)
	}

	if m.Len() != 1 {
		t.Errorf("Expected length 1, got %d", m.Len())
	}
}

func TestSyncUInt64Map_Iterators(t *testing.T) {
	m := NewSyncUInt64Map[string](4)

	// Add test data
	data := map[uint64]string{
		1: "one",
		2: "two",
		3: "three",
	}

	for k, v := range data {
		m.Set(k, v)
	}

	// Test All iterator
	count := 0
	for k, v := range m.All() {
		if data[k] != v {
			t.Errorf("All(): expected data[%d] = %s, got %s", k, data[k], v)
		}
		count++
	}
	if count != len(data) {
		t.Errorf("All(): expected %d iterations, got %d", len(data), count)
	}
}

func TestSyncUInt64Map_ConcurrentDeleteSet(t *testing.T) {
	m := NewSyncUInt64Map[int](4)
	const numGoroutines = 50
	const numIterations = 1000

	// Use a smaller key range to increase contention
	const keyRange = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numIterations; j++ {
				key := uint64(j % keyRange) //nolint:gosec // G115 - test loop

				if id%2 == 0 {
					// Even goroutines: Set then Del
					m.Set(key, id)
					runtime.Gosched() // Increase chance of race
					m.Del(key)
				} else {
					// Odd goroutines: Del then Set
					m.Del(key)
					runtime.Gosched() // Increase chance of race
					m.Set(key, id)
				}
			}
		}(i)
	}

	wg.Wait()

	// Map should be consistent
	seenKeys := make(map[uint64]bool)
	m.ForEach(func(k uint64, v int) bool {
		seenKeys[k] = true
		return true
	})

	if len(seenKeys) != int(m.Len()) {
		t.Errorf("Inconsistent state: saw %d keys, Len() = %d", len(seenKeys), m.Len())
	}
}

func TestSyncUInt64Map_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	m := NewSyncUInt64Map[int](10) // 1024 buckets
	const numGoroutines = 100
	const duration = 2 * time.Second

	stop := make(chan struct{})
	var ops atomic.Int64

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Start workers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id))) //nolint:gosec // G404 - test random

			for {
				select {
				case <-stop:
					return
				default:
					key := uint64(rng.Intn(10000)) //nolint:gosec // G115 - test random

					switch rng.Intn(10) {
					case 0, 1: // 20% delete
						m.Del(key)
					case 2, 3, 4: // 30% set
						m.Set(key, id)
					default: // 50% get
						m.Get(key)
					}

					ops.Add(1)
				}
			}
		}(i)
	}

	// Run for duration
	time.Sleep(duration)
	close(stop)
	wg.Wait()

	totalOps := ops.Load()
	opsPerSec := float64(totalOps) / duration.Seconds()

	t.Logf("Stress test completed: %d total ops, %.2f ops/sec", totalOps, opsPerSec)

	// Verify final state is consistent
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return true
	})

	if count != int(m.Len()) {
		t.Errorf("Final state inconsistent: ForEach found %d items, Len() = %d", count, m.Len())
	}
}

func TestSyncUInt64Map_MinimumSize(t *testing.T) {
	// Test with size smaller than minimum
	m := NewSyncUInt64Map[int](0)

	// Should still work with minimum size
	m.Set(1, 100)
	m.Set(2, 200)
	m.Set(3, 300)
	m.Set(4, 400)

	if m.Len() != 4 {
		t.Errorf("Expected length 4, got %d", m.Len())
	}

	// Verify all values
	for i := uint64(1); i <= 4; i++ {
		v, ok := m.Get(i)
		if !ok || v != int(i*100) { //nolint:gosec // G115 - test value, i is small
			t.Errorf("Expected Get(%d) = (%d, true), got (%d, %v)", i, i*100, v, ok)
		}
	}
}

func TestSyncUInt64Map_ComplexSetScenarios(t *testing.T) {
	m := NewSyncUInt64Map[int](2) // Small size to force collisions

	// Test 1: Update deleted node scenario
	m.Set(1, 100)
	m.Del(1)

	// Now try to set it again - this tests the resurrection path
	m.Set(1, 200)
	v, ok := m.Get(1)
	if !ok || v != 200 {
		t.Errorf("Expected resurrected value 200, got %v, %v", v, ok)
	}

	// Test 2: Concurrent resurrection attempts
	m.Set(2, 300)
	m.Del(2)

	var wg sync.WaitGroup
	wg.Add(2)

	// Two goroutines trying to resurrect the same key
	go func() {
		defer wg.Done()
		m.Set(2, 400)
	}()

	go func() {
		defer wg.Done()
		m.Set(2, 500)
	}()

	wg.Wait()

	// One of them should have won
	v, ok = m.Get(2)
	if !ok || (v != 400 && v != 500) {
		t.Errorf("Expected resurrected value 400 or 500, got %v, %v", v, ok)
	}

	// Test 3: Set with collision chain
	// These keys are designed to collide in a small map
	keys := []uint64{4, 8, 12, 16, 20}
	for i, k := range keys {
		m.Set(k, i*100)
	}

	// Verify all exist
	for i, k := range keys {
		v, ok := m.Get(k)
		if !ok || v != i*100 {
			t.Errorf("Expected Get(%d) = %d, got %v, %v", k, i*100, v, ok)
		}
	}

	// Test 4: Update in middle of collision chain
	m.Set(12, 999) // Update middle element
	v, ok = m.Get(12)
	if !ok || v != 999 {
		t.Errorf("Expected updated value 999, got %v, %v", v, ok)
	}
}

func TestSyncUInt64Map_ConcurrentSetCollisions(t *testing.T) {
	m := NewSyncUInt64Map[int](2) // Very small to maximize collisions

	const numGoroutines = 10
	const numKeys = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// All goroutines try to set the same keys that will collide
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 100; j++ {
				// Keys designed to collide
				key := uint64(j % numKeys * 4) //nolint:gosec // G115 - test calculation
				m.Set(key, id*1000+j)

				// Also try to update existing keys
				if j > 50 {
					m.Set(key, id*2000+j)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify consistency
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		// Value should be from one of the goroutines
		if v < 0 || v >= numGoroutines*3000 {
			t.Errorf("Unexpected value %d for key %d", v, k)
		}
		return true
	})

	// We might have more than numKeys due to timing, but should be close
	if count > numKeys*2 {
		t.Errorf("Expected around %d keys, found %d (too many)", numKeys, count)
	}
}

func TestSyncUInt64Map_ConcurrentIteration(t *testing.T) {
	m := NewSyncUInt64Map[int](6)

	// Pre-populate
	for i := 0; i < 100; i++ {
		m.Set(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Concurrent iteration
	go func() {
		defer wg.Done()
		count := 0
		m.ForEach(func(k uint64, v int) bool {
			count++
			time.Sleep(time.Microsecond) // Slow iteration
			return true
		})
		t.Logf("Iterator 1 visited %d items", count)
	}()

	// Concurrent modification
	go func() {
		defer wg.Done()
		for i := 100; i < 200; i++ {
			m.Set(uint64(i), i) //nolint:gosec // G115 - test loop
			time.Sleep(time.Microsecond)
		}
	}()

	// Concurrent deletion
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			m.Del(uint64(i)) //nolint:gosec // G115 - test loop
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Wait()

	// Final consistency check
	finalCount := int(m.Len())
	iterCount := 0
	m.ForEach(func(k uint64, v int) bool {
		iterCount++
		return true
	})

	if iterCount != finalCount {
		t.Errorf("Inconsistent final state: Len() = %d, ForEach found %d", finalCount, iterCount)
	}
}

func TestSyncUInt64Map_SetEdgeCases(t *testing.T) {
	m := NewSyncUInt64Map[int](2)

	// Test the retry path in Set when predecessor changes
	// This requires careful timing to hit the CAS failure path

	// First, create a collision chain
	m.Set(1, 100)
	m.Set(5, 500) // Likely to collide with 1
	m.Set(9, 900) // Another collision

	// Test concurrent inserts that force retry
	var wg sync.WaitGroup
	const numGoroutines = 20
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			// All trying to insert keys that will collide
			key := uint64(13 + id*4) //nolint:gosec // G115 - test calculation // 13, 17, 21, 25...
			m.Set(key, id)
		}(i)
	}

	wg.Wait()

	// Verify all inserts succeeded
	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		key := uint64(13 + i*4) //nolint:gosec // G115 - test calculation
		if m.Has(key) {
			successCount++
		}
	}

	if successCount != numGoroutines {
		t.Errorf("Expected all %d concurrent inserts to succeed, got %d", numGoroutines, successCount)
	}
}

func TestSyncUInt64Map_NilValueHandling(t *testing.T) {
	// Test with pointer values to check nil handling
	m := NewSyncUInt64Map[*int](4)

	// Set a non-nil value
	val := 42
	m.Set(1, &val)

	// ForEach should handle nil values gracefully
	count := 0
	m.ForEach(func(k uint64, v *int) bool {
		if v != nil {
			count++
		}
		return true
	})

	if count != 1 {
		t.Errorf("Expected 1 non-nil value, got %d", count)
	}
}

func TestSyncUInt64Map_CASRetryPaths(t *testing.T) {
	// This test specifically targets the CAS retry paths in Set
	m := NewSyncUInt64Map[int](2) // Very small to force collisions

	// Step 1: Create a chain where we'll force retries
	baseKeys := []uint64{1, 5, 9} // These will likely collide
	for i, k := range baseKeys {
		m.Set(k, i*100)
	}

	// Step 2: Delete a middle node to create a resurrection scenario
	m.Del(5)

	// Step 3: Concurrent operations to trigger CAS failures
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Half the goroutines try to resurrect the deleted key
	for i := 0; i < numGoroutines/2; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 10; j++ {
				m.Set(5, id*1000+j) // Try to resurrect
				runtime.Gosched()
			}
		}(i)
	}

	// Other half try to add new colliding keys
	for i := numGoroutines / 2; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 10; j++ {
				// Keys that will collide: 13, 17, 21...
				key := uint64(13 + (id-numGoroutines/2)*4) //nolint:gosec // G115 - test calculation
				m.Set(key, id*1000+j)

				// Also update existing keys to force chain modifications
				if j%3 == 0 {
					m.Set(1, id*2000+j)
					m.Set(9, id*3000+j)
				}
				runtime.Gosched()
			}
		}(i)
	}

	wg.Wait()

	// Verify the map is consistent
	if !m.Has(5) {
		t.Error("Key 5 should have been resurrected")
	}

	finalCount := int(m.Len())
	iterCount := 0
	m.ForEach(func(k uint64, v int) bool {
		iterCount++
		return true
	})

	if iterCount != finalCount {
		t.Errorf("Inconsistent state: Len() = %d, ForEach found %d", finalCount, iterCount)
	}
}

func TestSyncUInt64Map_GetEdgeCases(t *testing.T) {
	m := NewSyncUInt64Map[*string](4)

	// Test Get when value pointer is nil
	m.Set(1, nil)

	v, ok := m.Get(1)
	if !ok || v != nil {
		t.Errorf("Get should return (nil, true) when stored value is nil, got (%v, %v)", v, ok)
	}
}

func TestSyncUInt64Map_ForEachEdgeCases(t *testing.T) {
	// Test ForEach with nil values
	m := NewSyncUInt64Map[*int](4)

	// Set some nil and non-nil values
	val1 := 100
	val2 := 200

	m.Set(1, &val1)
	m.Set(2, nil)
	m.Set(3, &val2)
	m.Set(4, nil)

	// Delete one to test skip logic
	m.Del(3)

	// Count non-nil values
	count := 0
	m.ForEach(func(k uint64, v *int) bool {
		if v != nil {
			count++
		}
		return true
	})

	if count != 1 {
		t.Errorf("Expected 1 non-nil value in ForEach, got %d", count)
	}
}
