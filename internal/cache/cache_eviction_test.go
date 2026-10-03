package cache

import (
	"testing"
	"time"
)

func TestCacheEviction(t *testing.T) {
	// Create a small cache to test eviction
	cacheSize := 100
	c := New[any](cacheSize)

	// Fill the cache to capacity
	for i := 0; i < cacheSize; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	if c.Len() != cacheSize {
		t.Errorf("Expected cache size %d, got %d", cacheSize, c.Len())
	}

	// Add more items to trigger eviction
	for i := cacheSize; i < cacheSize+50; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop

		// Check size after each batch of additions
		if i%10 == 0 {
			currentLen := c.Len()
			// Allow some tolerance since eviction is sampled
			if currentLen > cacheSize+cacheSize/5 { // 20% tolerance
				t.Errorf("Cache size %d exceeds max size %d by more than 20%%", currentLen, cacheSize)
			}
		}
	}

	// Final size check - should be close to max size
	finalLen := c.Len()
	if finalLen > cacheSize+cacheSize/10 { // 10% tolerance
		t.Errorf("Final cache size %d exceeds max size %d by more than 10%%", finalLen, cacheSize)
	}

	// With random eviction, we can't guarantee which items remain
	// Just verify that some items are still retrievable
	found := 0
	for i := 0; i < cacheSize+50; i++ {
		if _, ok := c.Get(uint64(i)); ok { //nolint:gosec // G115 - test loop
			found++
		}
	}

	if found == 0 {
		t.Error("No items found in cache after eviction")
	}

	// The number of items found should be close to the cache size
	if found < cacheSize/2 {
		t.Errorf("Too few items remaining: %d, expected around %d", found, cacheSize)
	}
}

func TestCacheEvictionSmallCache(t *testing.T) {
	// Test with very small cache
	c := New[any](1)

	c.Add(1, "one")
	if c.Len() != 1 {
		t.Error("Cache should have 1 item")
	}

	c.Add(2, "two")
	// Should have evicted the first item
	if c.Len() > 1 {
		t.Errorf("Small cache should maintain size limit, got %d", c.Len())
	}
}

func TestCacheEvictionConcurrent(t *testing.T) {
	cacheSize := 1000
	c := New[any](cacheSize)

	// Concurrently add many items
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(start int) {
			for j := 0; j < 200; j++ {
				c.Add(uint64(start*1000+j), j) //nolint:gosec // G115 - test loop
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check that cache size is bounded
	if c.Len() > cacheSize*2 {
		t.Errorf("Cache size %d significantly exceeds max size %d", c.Len(), cacheSize)
	}
}

func BenchmarkCacheWithEviction(b *testing.B) {
	c := New[any](10000) // 10K max size

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// This will trigger eviction periodically
			c.Add(uint64(i), i) //nolint:gosec // G115 - benchmark loop
			i++
		}
	})
}

// TestOnEvictCountsCapacityEvictions: the owner hears of every entry an
// insert evicts to stay within capacity, through Add, AddUntil and
// AddIfAbsent alike, and of nothing else: replacing a key, removing one or
// an insert under capacity evicts nothing.
func TestOnEvictCountsCapacityEvictions(t *testing.T) {
	const size = 64
	c := NewWithExpiry[*int](size, time.Hour, func(*int) *ExpiryMark { return new(ExpiryMark) })
	var evicted int
	c.OnEvict(func(n int) { evicted += n })

	for i := range size {
		v := i
		c.Add(uint64(i)+1, &v) //nolint:gosec // small test keys
	}
	c.Add(1, new(int)) // replace
	c.Remove(2)
	if evicted != 0 {
		t.Fatalf("evicted %d under capacity", evicted)
	}

	for i := size; i < 4*size; i++ {
		v := i
		switch i % 3 {
		case 0:
			c.Add(uint64(i)+1, &v) //nolint:gosec // small test keys
		case 1:
			c.AddUntil(uint64(i)+1, &v, time.Now().Add(time.Minute)) //nolint:gosec // small test keys
		default:
			c.AddIfAbsent(uint64(i)+1, &v) //nolint:gosec // small test keys
		}
	}
	inserted := 4*size - 1 // the removal freed one slot
	if want := inserted - c.Len(); evicted != want {
		t.Fatalf("evicted %d, want %d (inserted %d, holding %d)", evicted, want, inserted, c.Len())
	}
}
