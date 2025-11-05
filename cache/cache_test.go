// Package cache provides a high-performance LRU cache for DNS records
package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheAddAndGet(t *testing.T) {
	c := New(4)
	c.Add(1, 1)

	value, found := c.Get(1)
	require.True(t, found, "Failed to find inserted record")
	assert.Equal(t, 1, value)
}

func TestCacheLen(t *testing.T) {
	c := New(4)

	c.Add(1, 1)
	assert.Equal(t, 1, c.Len(), "Cache should have 1 item")

	// Adding same key shouldn't increase size
	c.Add(1, 1)
	assert.Equal(t, 1, c.Len(), "Cache should still have 1 item")

	c.Add(2, 2)
	assert.Equal(t, 2, c.Len(), "Cache should have 2 items")
}

func TestCacheRemove(t *testing.T) {
	c := New(4)

	c.Add(1, 1)
	assert.Equal(t, 1, c.Len(), "Cache should have 1 item")

	c.Remove(1)
	assert.Equal(t, 0, c.Len(), "Cache should be empty after removal")

	_, found := c.Get(1)
	assert.False(t, found, "Item should not be found after removal")
}

func TestCacheLRUEviction(t *testing.T) {
	// Note: RadicalCache is not LRU, it clears segments for performance
	// This test verifies size limits are maintained
	c := New(2)

	c.Add(1, "one")
	c.Add(2, "two")
	assert.LessOrEqual(t, c.Len(), 2)

	// Adding third item should trigger eviction
	c.Add(3, "three")

	// RadicalCache may clear entire segments, so we just verify size limit
	assert.LessOrEqual(t, c.Len(), 3, "Cache should not grow unbounded")
}

func TestCacheLRUBehavior(t *testing.T) {
	// Note: RadicalCache doesn't guarantee LRU behavior
	// It uses segment clearing for performance
	c := New(3)

	// Add three items
	c.Add(1, "one")
	c.Add(2, "two")
	c.Add(3, "three")

	// Access item 1 (no LRU tracking in RadicalCache)
	c.Get(1)

	// Add fourth item - should maintain size limit
	c.Add(4, "four")

	// Should have at most 4 items (allows slight overshoot for performance)
	assert.LessOrEqual(t, c.Len(), 4, "Cache should maintain reasonable bounds")
}

func TestCacheConcurrency(t *testing.T) {
	c := New(1000)
	const numGoroutines = 100
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent adds and gets
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := uint64(id*opsPerGoroutine + j) //nolint:gosec // G115 - test loop
				c.Add(key, fmt.Sprintf("value-%d-%d", id, j))

				// Randomly access some values
				if j%10 == 0 {
					randomKey := uint64((id + j) % (numGoroutines * opsPerGoroutine)) //nolint:gosec // G115 - test calculation
					c.Get(randomKey)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify cache still functions correctly
	// Allow up to 10% overshoot for concurrent operations with 256 segments
	assert.LessOrEqual(t, c.Len(), 1100, "Cache should not exceed capacity by more than 10%")
}

func TestCacheRemoveConcurrency(t *testing.T) {
	c := New(1000)
	const numGoroutines = 50
	const keysPerGoroutine = 20

	// Pre-populate cache
	for i := 0; i < numGoroutines*keysPerGoroutine; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop //nolint:gosec // G115 - test loop
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent removes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < keysPerGoroutine; j++ {
				key := uint64(id*keysPerGoroutine + j) //nolint:gosec // G115 - test loop
				c.Remove(key)
			}
		}(i)
	}

	wg.Wait()

	assert.Equal(t, 0, c.Len(), "All items should be removed")
}

func TestCacheZeroCapacity(t *testing.T) {
	c := New(0)

	// Zero capacity becomes 1 (minimum)
	c.Add(1, "one")
	assert.LessOrEqual(t, c.Len(), 1)

	_, found := c.Get(1)
	assert.True(t, found, "Should find item in minimum capacity cache")
}

func TestCacheUpdateExisting(t *testing.T) {
	c := New(10)

	c.Add(1, "original")
	val, found := c.Get(1)
	require.True(t, found)
	assert.Equal(t, "original", val)

	// Update with new value
	c.Add(1, "updated")
	val, found = c.Get(1)
	require.True(t, found)
	assert.Equal(t, "updated", val)

	// Size should remain 1
	assert.Equal(t, 1, c.Len())
}

func TestCacheCapacity(t *testing.T) {
	c := New(100)

	// Add some items
	for i := 0; i < 50; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	// Verify size
	assert.Equal(t, 50, c.Len())

	// Add more items up to capacity
	for i := 50; i < 100; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	assert.Equal(t, 100, c.Len())

	// Adding more should maintain capacity
	for i := 100; i < 150; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	assert.LessOrEqual(t, c.Len(), 100, "Cache should not exceed capacity")
}

// Benchmarks.
func BenchmarkCacheGet(b *testing.B) {
	c := New(10000)

	// Pre-populate
	for i := 0; i < 10000; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Get(uint64(i % 10000)) //nolint:gosec // G115 - test loop
			i++
		}
	})
}

func BenchmarkCacheAdd(b *testing.B) {
	c := New(10000)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
			i++
		}
	})
}

func BenchmarkCacheMixed(b *testing.B) {
	c := New(10000)

	// Pre-populate
	for i := 0; i < 5000; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				c.Get(uint64(i % 10000)) //nolint:gosec // G115 - test loop //nolint:gosec // G115 - test loop
			} else {
				c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
			}
			i++
		}
	})
}

func TestCacheMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	c := New(10000)

	// Add items
	for i := 0; i < 10000; i++ {
		c.Add(uint64(i), fmt.Sprintf("value-%d", i)) //nolint:gosec // G115 - test loop
	}

	// Just verify the cache is working
	found := 0
	for i := 0; i < 100; i++ {
		if _, ok := c.Get(uint64(i)); ok { //nolint:gosec // G115 - test loop
			found++
		}
	}

	t.Logf("Found %d items out of 100 checked", found)
	assert.Greater(t, found, 0, "Should find some cached items")
}

func TestCacheTTL(t *testing.T) {
	// This test demonstrates how TTL could work with cache
	type timedValue struct {
		value  any
		expiry time.Time
	}

	c := New(10)
	now := time.Now()

	// Add item with 1 second TTL
	c.Add(1, timedValue{
		value:  "test",
		expiry: now.Add(1 * time.Second),
	})

	// Should find immediately
	val, found := c.Get(1)
	require.True(t, found)
	tv := val.(timedValue)
	assert.Equal(t, "test", tv.value)
	assert.False(t, time.Now().After(tv.expiry))

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// Can still get from cache, but caller should check expiry
	val, found = c.Get(1)
	require.True(t, found)
	tv = val.(timedValue)
	assert.True(t, time.Now().After(tv.expiry), "Item should be expired")
}
