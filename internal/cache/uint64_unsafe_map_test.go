package cache

import (
	"reflect"
	"slices"
	"testing"
)

func TestUInt64MapPutIfNotExists(t *testing.T) {
	m := NewUInt64Map[string](16)

	// First insert should succeed
	val, inserted := m.PutIfNotExists(1, "first")
	if !(inserted) {
		t.Errorf("inserted is false")
	}
	if !reflect.DeepEqual("first", val) {
		t.Errorf("val = %v, want %v", val, "first")
	}
	if !reflect.DeepEqual(1, m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), 1)
	}

	// Second insert with same key should fail
	val, inserted = m.PutIfNotExists(1, "second")
	if inserted {
		t.Errorf("inserted is true")
	}
	if !reflect.DeepEqual("first", val) {
		t.Errorf("val = %v, want %v", val, "first")
	} // Should return existing value
	if !reflect.DeepEqual(1, m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), 1)
	}

	// Insert different key should succeed
	val, inserted = m.PutIfNotExists(2, "another")
	if !(inserted) {
		t.Errorf("inserted is false")
	}
	if !reflect.DeepEqual("another", val) {
		t.Errorf("val = %v, want %v", val, "another")
	}
	if !reflect.DeepEqual(2, m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), 2)
	}
}

func TestUInt64MapPutIfNotExistsZeroKey(t *testing.T) {
	m := NewUInt64Map[string](16)

	// Zero key first insert
	val, inserted := m.PutIfNotExists(0, "zero")
	if !(inserted) {
		t.Errorf("inserted is false")
	}
	if !reflect.DeepEqual("zero", val) {
		t.Errorf("val = %v, want %v", val, "zero")
	}

	// Zero key second insert should fail
	val, inserted = m.PutIfNotExists(0, "another")
	if inserted {
		t.Errorf("inserted is true")
	}
	if !reflect.DeepEqual("zero", val) {
		t.Errorf("val = %v, want %v", val, "zero")
	}
}

func TestUInt64MapPutIfNotExistsWithCollisions(t *testing.T) {
	m := NewUInt64Map[int](8) // Small capacity to force collisions

	// Add many items to force collisions
	for i := 1; i <= 20; i++ {
		val, inserted := m.PutIfNotExists(uint64(i), i*10) //nolint:gosec // G115 - test values are small
		if !(inserted) {
			t.Errorf("inserted is false")
		}
		if !reflect.DeepEqual(i*10, val) {
			t.Errorf("val = %v, want %v", val, i*10)
		}
	}

	// Try to insert existing keys
	for i := 1; i <= 20; i++ {
		val, inserted := m.PutIfNotExists(uint64(i), i*100) //nolint:gosec // G115 - test values are small
		if inserted {
			t.Errorf("inserted is true")
		}
		if !reflect.DeepEqual(i*10, val) {
			t.Errorf("val = %v, want %v", val, i*10)
		} // Original value
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

	if len(collected) != 4 {
		t.Errorf("len(collected) = %d, want %d", len(collected), 4)
	}
	if !reflect.DeepEqual(100, collected[1]) {
		t.Errorf("collected[1] = %v, want %v", collected[1], 100)
	}
	if !reflect.DeepEqual(200, collected[2]) {
		t.Errorf("collected[2] = %v, want %v", collected[2], 200)
	}
	if !reflect.DeepEqual(300, collected[3]) {
		t.Errorf("collected[3] = %v, want %v", collected[3], 300)
	}
	if !reflect.DeepEqual(999, collected[0]) {
		t.Errorf("collected[0] = %v, want %v", collected[0], 999)
	}
}

func TestUInt64MapAllNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	count := 0
	for range m.All() {
		count++
	}
	if !reflect.DeepEqual(0, count) {
		t.Errorf("count = %v, want %v", count, 0)
	}
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

	if len(keys) != 4 {
		t.Errorf("len(keys) = %d, want %d", len(keys), 4)
	}
	for _, want := range []uint64{0, 10, 20, 30} {
		if !slices.Contains(keys, want) {
			t.Errorf("keys %v do not contain %d", keys, want)
		}
	}
}

func TestUInt64MapKeysNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	count := 0
	for range m.Keys() {
		count++
	}
	if !reflect.DeepEqual(0, count) {
		t.Errorf("count = %v, want %v", count, 0)
	}
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
	if !reflect.DeepEqual(3, count) {
		t.Errorf("count = %v, want %v", count, 3)
	}
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

	if len(values) != 4 {
		t.Errorf("len(values) = %d, want %d", len(values), 4)
	}
	for _, want := range []string{"zero", "one", "two", "three"} {
		if !slices.Contains(values, want) {
			t.Errorf("values %v do not contain %q", values, want)
		}
	}
}

func TestUInt64MapValuesNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	count := 0
	for range m.Values() {
		count++
	}
	if !reflect.DeepEqual(0, count) {
		t.Errorf("count = %v, want %v", count, 0)
	}
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
	if !reflect.DeepEqual(3, count) {
		t.Errorf("count = %v, want %v", count, 3)
	}
}

func TestUInt64MapHasWithCollisions(t *testing.T) {
	m := NewUInt64Map[int](8) // Small capacity

	// Add items to create collision chains
	for i := uint64(1); i <= 20; i++ {
		m.Put(i, int(i))
	}

	// Test Has for existing keys
	for i := uint64(1); i <= 20; i++ {
		if !(m.Has(i)) {
			t.Errorf("m.Has(i) is false")
		}
	}

	// Test Has for non-existing keys
	if m.Has(100) {
		t.Errorf("m.Has(100) is true")
	}
	if m.Has(200) {
		t.Errorf("m.Has(200) is true")
	}
}

func TestUInt64MapHasZeroKey(t *testing.T) {
	m := NewUInt64Map[int](16)

	if m.Has(0) {
		t.Errorf("m.Has(0) is true")
	}

	m.Put(0, 100)
	if !(m.Has(0)) {
		t.Errorf("m.Has(0) is false")
	}

	m.Del(0)
	if m.Has(0) {
		t.Errorf("m.Has(0) is true")
	}
}

func TestUInt64MapHasNilMap(t *testing.T) {
	var m *UInt64Map[int]
	if m.Has(1) {
		t.Errorf("m.Has(1) is true")
	}
	if m.Has(0) {
		t.Errorf("m.Has(0) is true")
	}
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

	if !reflect.DeepEqual(5, count) {
		t.Errorf("count = %v, want %v", count, 5)
	}
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

	if len(keys) != 3 {
		t.Errorf("len(keys) = %d, want %d", len(keys), 3)
	}
	if !slices.Contains(keys, uint64(0)) {
		t.Errorf("keys %v do not contain 0", keys)
	}
}

func TestUInt64MapForEachNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic
	count := 0
	m.ForEach(func(k uint64, v int) bool {
		count++
		return true
	})
	if !reflect.DeepEqual(0, count) {
		t.Errorf("count = %v, want %v", count, 0)
	}
}

func TestUInt64MapClearNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic on nil map
	m.Clear()
}

func TestUInt64MapLenNilMap(t *testing.T) {
	var m *UInt64Map[int]
	if !reflect.DeepEqual(0, m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), 0)
	}
}

func TestUInt64MapGetNilMap(t *testing.T) {
	var m *UInt64Map[int]

	val, found := m.Get(1)
	if found {
		t.Errorf("found is true")
	}
	if !reflect.DeepEqual(0, val) {
		t.Errorf("val = %v, want %v", val, 0)
	}

	val, found = m.Get(0)
	if found {
		t.Errorf("found is true")
	}
	if !reflect.DeepEqual(0, val) {
		t.Errorf("val = %v, want %v", val, 0)
	}
}

func TestUInt64MapDelNilMap(t *testing.T) {
	var m *UInt64Map[int]

	// Should not panic and return false
	if m.Del(1) {
		t.Errorf("m.Del(1) is true")
	}
	if m.Del(0) {
		t.Errorf("m.Del(0) is true")
	}
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
		if !(found) {
			t.Errorf("found is false")
		}
		if !reflect.DeepEqual(i*10, val) {
			t.Errorf("val = %v, want %v", val, i*10)
		}
	}

	if !reflect.DeepEqual(100, m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), 100)
	}
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
	if !(found) {
		t.Errorf("found is false")
	}
	if !reflect.DeepEqual(999, val) {
		t.Errorf("val = %v, want %v", val, 999)
	}
}
