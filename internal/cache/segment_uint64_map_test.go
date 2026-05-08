package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSegmentUInt64MapPutIfNotExists(t *testing.T) {
	m := NewSegmentUInt64Map[string](4, 100)

	// First insert should succeed
	val, inserted := m.PutIfNotExists(1, "first")
	assert.True(t, inserted)
	assert.Equal(t, "first", val)
	assert.Equal(t, int64(1), m.Len())

	// Second insert with same key should fail
	val, inserted = m.PutIfNotExists(1, "second")
	assert.False(t, inserted)
	assert.Equal(t, "first", val) // Should return existing value
	assert.Equal(t, int64(1), m.Len())

	// Insert different key should succeed
	val, inserted = m.PutIfNotExists(2, "another")
	assert.True(t, inserted)
	assert.Equal(t, "another", val)
	assert.Equal(t, int64(2), m.Len())
}

func TestSegmentUInt64MapAll(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	// Add some values
	m.Set(1, 100)
	m.Set(2, 200)
	m.Set(3, 300)

	// Collect all key-value pairs using All iterator
	collected := make(map[uint64]int)
	for k, v := range m.All() {
		collected[k] = v
	}

	assert.Len(t, collected, 3)
	assert.Equal(t, 100, collected[1])
	assert.Equal(t, 200, collected[2])
	assert.Equal(t, 300, collected[3])
}

func TestSegmentUInt64MapKeys(t *testing.T) {
	m := NewSegmentUInt64Map[string](4, 100)

	m.Set(10, "a")
	m.Set(20, "b")
	m.Set(30, "c")

	// Collect all keys using Keys iterator
	keys := make([]uint64, 0)
	for k := range m.Keys() {
		keys = append(keys, k)
	}

	assert.Len(t, keys, 3)
	assert.Contains(t, keys, uint64(10))
	assert.Contains(t, keys, uint64(20))
	assert.Contains(t, keys, uint64(30))
}

func TestSegmentUInt64MapValues(t *testing.T) {
	m := NewSegmentUInt64Map[string](4, 100)

	m.Set(1, "one")
	m.Set(2, "two")
	m.Set(3, "three")

	// Collect all values using Values iterator
	values := make([]string, 0)
	for v := range m.Values() {
		values = append(values, v)
	}

	assert.Len(t, values, 3)
	assert.Contains(t, values, "one")
	assert.Contains(t, values, "two")
	assert.Contains(t, values, "three")
}

func TestSegmentUInt64MapClear(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	// Add some values
	m.Set(1, 100)
	m.Set(2, 200)
	m.Set(3, 300)
	assert.Equal(t, int64(3), m.Len())

	// Clear the map
	m.Clear()

	assert.Equal(t, int64(0), m.Len())

	// Verify keys are gone
	_, found := m.Get(1)
	assert.False(t, found)
	_, found = m.Get(2)
	assert.False(t, found)
	_, found = m.Get(3)
	assert.False(t, found)
}

func TestSegmentUInt64MapStop(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	m.Set(1, 100)

	// Stop is a no-op, should not panic
	m.Stop()

	// Map should still work after Stop
	val, found := m.Get(1)
	assert.True(t, found)
	assert.Equal(t, 100, val)
}

func TestSegmentUInt64MapForEachEarlyExit(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	// Add many values
	for i := uint64(1); i <= 100; i++ {
		m.Set(i, int(i))
	}

	// ForEach with early exit
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return count < 5 // Stop after 5 iterations
	})

	assert.Equal(t, 5, count)
}

func TestSegmentUInt64MapSegmentPowerBounds(t *testing.T) {
	// Test minimum segment power (should be clamped to 4)
	m1 := NewSegmentUInt64Map[int](1, 100)
	assert.Equal(t, 16, m1.SegmentCount()) // 2^4 = 16

	// Test maximum segment power (should be clamped to 8)
	m2 := NewSegmentUInt64Map[int](10, 100)
	assert.Equal(t, 256, m2.SegmentCount()) // 2^8 = 256

	// Test valid segment power
	m3 := NewSegmentUInt64Map[int](6, 100)
	assert.Equal(t, 64, m3.SegmentCount()) // 2^6 = 64
}

func TestSegmentUInt64MapClearSegmentOutOfBounds(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	m.Set(1, 100)

	// Clear with invalid index should not panic
	m.ClearSegment(-1)
	m.ClearSegment(1000)

	// Original value should still exist
	val, found := m.Get(1)
	assert.True(t, found)
	assert.Equal(t, 100, val)
}
