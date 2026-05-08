package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUInt64MapPutIfNotExists(t *testing.T) {
	m := NewUInt64Map[string](16)

	// First insert should succeed
	val, inserted := m.PutIfNotExists(1, "first")
	assert.True(t, inserted)
	assert.Equal(t, "first", val)
	assert.Equal(t, 1, m.Len())

	// Second insert with same key should fail
	val, inserted = m.PutIfNotExists(1, "second")
	assert.False(t, inserted)
	assert.Equal(t, "first", val) // Should return existing value
	assert.Equal(t, 1, m.Len())

	// Insert different key should succeed
	val, inserted = m.PutIfNotExists(2, "another")
	assert.True(t, inserted)
	assert.Equal(t, "another", val)
	assert.Equal(t, 2, m.Len())
}

func TestUInt64MapPutIfNotExistsZeroKey(t *testing.T) {
	m := NewUInt64Map[string](16)

	// Zero key first insert
	val, inserted := m.PutIfNotExists(0, "zero")
	assert.True(t, inserted)
	assert.Equal(t, "zero", val)

	// Zero key second insert should fail
	val, inserted = m.PutIfNotExists(0, "another")
	assert.False(t, inserted)
	assert.Equal(t, "zero", val)
}

func TestUInt64MapPutIfNotExistsWithCollisions(t *testing.T) {
	m := NewUInt64Map[int](8) // Small capacity to force collisions

	// Add many items to force collisions
	for i := 1; i <= 20; i++ {
		val, inserted := m.PutIfNotExists(uint64(i), i*10) //nolint:gosec // G115 - test values are small
		assert.True(t, inserted)
		assert.Equal(t, i*10, val)
	}

	// Try to insert existing keys
	for i := 1; i <= 20; i++ {
		val, inserted := m.PutIfNotExists(uint64(i), i*100) //nolint:gosec // G115 - test values are small
		assert.False(t, inserted)
		assert.Equal(t, i*10, val) // Original value
	}
}

func TestUInt64MapAll(t *testing.T) {
	m := NewUInt64Map[int](16)

	m.Put(1, 100)
	m.Put(2, 200)
	m.Put(3, 300)
	m.Put(0, 999) // Zero key

	// Collect all key-value pairs using All iterator
	collected := make(map[uint64]int)
	for k, v := range m.All() {
		collected[k] = v
	}

	assert.Len(t, collected, 4)
	assert.Equal(t, 100, collected[1])
	assert.Equal(t, 200, collected[2])
	assert.Equal(t, 300, collected[3])
	assert.Equal(t, 999, collected[0])
}

func TestUInt64MapAllNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	count := 0
	for range m.All() {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestUInt64MapKeys(t *testing.T) {
	m := NewUInt64Map[string](16)

	m.Put(10, "a")
	m.Put(20, "b")
	m.Put(30, "c")
	m.Put(0, "zero") // Zero key

	// Collect all keys using Keys iterator
	keys := make([]uint64, 0)
	for k := range m.Keys() {
		keys = append(keys, k)
	}

	assert.Len(t, keys, 4)
	assert.Contains(t, keys, uint64(0))
	assert.Contains(t, keys, uint64(10))
	assert.Contains(t, keys, uint64(20))
	assert.Contains(t, keys, uint64(30))
}

func TestUInt64MapKeysNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	count := 0
	for range m.Keys() {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestUInt64MapKeysEarlyExit(t *testing.T) {
	m := NewUInt64Map[int](16)

	for i := uint64(1); i <= 10; i++ {
		m.Put(i, int(i))
	}

	// Early exit from Keys iterator
	count := 0
	for range m.Keys() {
		count++
		if count >= 3 {
			break
		}
	}
	assert.Equal(t, 3, count)
}

func TestUInt64MapValues(t *testing.T) {
	m := NewUInt64Map[string](16)

	m.Put(1, "one")
	m.Put(2, "two")
	m.Put(3, "three")
	m.Put(0, "zero") // Zero key

	// Collect all values using Values iterator
	values := make([]string, 0)
	for v := range m.Values() {
		values = append(values, v)
	}

	assert.Len(t, values, 4)
	assert.Contains(t, values, "zero")
	assert.Contains(t, values, "one")
	assert.Contains(t, values, "two")
	assert.Contains(t, values, "three")
}

func TestUInt64MapValuesNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	count := 0
	for range m.Values() {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestUInt64MapValuesEarlyExit(t *testing.T) {
	m := NewUInt64Map[int](16)

	m.Put(0, 0) // Zero key
	for i := uint64(1); i <= 10; i++ {
		m.Put(i, int(i))
	}

	// Early exit from Values iterator
	count := 0
	for range m.Values() {
		count++
		if count >= 3 {
			break
		}
	}
	assert.Equal(t, 3, count)
}

func TestUInt64MapHasWithCollisions(t *testing.T) {
	m := NewUInt64Map[int](8) // Small capacity

	// Add items to create collision chains
	for i := uint64(1); i <= 20; i++ {
		m.Put(i, int(i))
	}

	// Test Has for existing keys
	for i := uint64(1); i <= 20; i++ {
		assert.True(t, m.Has(i))
	}

	// Test Has for non-existing keys
	assert.False(t, m.Has(100))
	assert.False(t, m.Has(200))
}

func TestUInt64MapHasZeroKey(t *testing.T) {
	m := NewUInt64Map[int](16)

	assert.False(t, m.Has(0))

	m.Put(0, 100)
	assert.True(t, m.Has(0))

	m.Del(0)
	assert.False(t, m.Has(0))
}

func TestUInt64MapHasNilMap(t *testing.T) {
	var m *UInt64Map[int]
	assert.False(t, m.Has(1))
	assert.False(t, m.Has(0))
}

func TestUInt64MapForEachEarlyExit(t *testing.T) {
	m := NewUInt64Map[int](16)

	for i := uint64(1); i <= 20; i++ {
		m.Put(i, int(i))
	}

	// Early exit from ForEach
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return count < 5
	})

	assert.Equal(t, 5, count)
}

func TestUInt64MapForEachWithZeroKey(t *testing.T) {
	m := NewUInt64Map[int](16)

	m.Put(0, 999) // Zero key first
	m.Put(1, 100)
	m.Put(2, 200)

	// ForEach should include zero key
	keys := make([]uint64, 0)
	m.ForEach(func(k uint64, v int) bool {
		keys = append(keys, k)
		return true
	})

	assert.Len(t, keys, 3)
	assert.Contains(t, keys, uint64(0))
}

func TestUInt64MapForEachNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count)
}

func TestUInt64MapClearNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	m.Clear()
}

func TestUInt64MapLenNilMap(t *testing.T) {
	var m *UInt64Map[int]
	assert.Equal(t, 0, m.Len())
}

func TestUInt64MapGetNilMap(t *testing.T) {
	var m *UInt64Map[int]

	val, found := m.Get(1)
	assert.False(t, found)
	assert.Equal(t, 0, val)

	val, found = m.Get(0)
	assert.False(t, found)
	assert.Equal(t, 0, val)
}

func TestUInt64MapDelNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic and return false
	assert.False(t, m.Del(1))
	assert.False(t, m.Del(0))
}

func TestUInt64MapGrow(t *testing.T) {
	m := NewUInt64Map[int](8) // Start small

	// Add many items to trigger growth
	for i := 1; i <= 100; i++ {
		m.Put(uint64(i), i*10) //nolint:gosec // G115 - test values are small
	}

	// Verify all items are still accessible
	for i := 1; i <= 100; i++ {
		val, found := m.Get(uint64(i)) //nolint:gosec // G115 - test values are small
		assert.True(t, found)
		assert.Equal(t, i*10, val)
	}

	assert.Equal(t, 100, m.Len())
}

func TestUInt64MapGrowWithZeroKey(t *testing.T) {
	m := NewUInt64Map[int](8)

	// Add zero key first
	m.Put(0, 999)

	// Add many items to trigger growth
	for i := uint64(1); i <= 50; i++ {
		m.Put(i, int(i))
	}

	// Zero key should still be accessible
	val, found := m.Get(0)
	assert.True(t, found)
	assert.Equal(t, 999, val)
}
