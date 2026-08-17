package cache

import (
	"reflect"
	"slices"
	"testing"
)

func TestSegmentUInt64MapPutIfNotExists(t *testing.T) {
	m := NewSegmentUInt64Map[string](4, 100)

	// First insert should succeed
	val, inserted := m.PutIfNotExists(1, "first")
	if !(inserted) {
		t.Errorf("inserted is false")
	}
	if !reflect.DeepEqual("first", val) {
		t.Errorf("val = %v, want %v", val, "first")
	}
	if !reflect.DeepEqual(int64(1), m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), int64(1))
	}

	// Second insert with same key should fail
	val, inserted = m.PutIfNotExists(1, "second")
	if inserted {
		t.Errorf("inserted is true")
	}
	if !reflect.DeepEqual("first", val) {
		t.Errorf("val = %v, want %v", val, "first")
	} // Should return existing value
	if !reflect.DeepEqual(int64(1), m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), int64(1))
	}

	// Insert different key should succeed
	val, inserted = m.PutIfNotExists(2, "another")
	if !(inserted) {
		t.Errorf("inserted is false")
	}
	if !reflect.DeepEqual("another", val) {
		t.Errorf("val = %v, want %v", val, "another")
	}
	if !reflect.DeepEqual(int64(2), m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), int64(2))
	}
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

	if len(collected) != 3 {
		t.Errorf("len(collected) = %d, want %d", len(collected), 3)
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

	if len(keys) != 3 {
		t.Errorf("len(keys) = %d, want %d", len(keys), 3)
	}
	for _, want := range []uint64{10, 20, 30} {
		if !slices.Contains(keys, want) {
			t.Errorf("keys %v do not contain %d", keys, want)
		}
	}
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

	if len(values) != 3 {
		t.Errorf("len(values) = %d, want %d", len(values), 3)
	}
	for _, want := range []string{"one", "two", "three"} {
		if !slices.Contains(values, want) {
			t.Errorf("values %v do not contain %q", values, want)
		}
	}
}

func TestSegmentUInt64MapClear(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	// Add some values
	m.Set(1, 100)
	m.Set(2, 200)
	m.Set(3, 300)
	if !reflect.DeepEqual(int64(3), m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), int64(3))
	}

	// Clear the map
	m.Clear()

	if !reflect.DeepEqual(int64(0), m.Len()) {
		t.Errorf("m.Len() = %v, want %v", m.Len(), int64(0))
	}

	// Verify keys are gone
	_, found := m.Get(1)
	if found {
		t.Errorf("found is true")
	}
	_, found = m.Get(2)
	if found {
		t.Errorf("found is true")
	}
	_, found = m.Get(3)
	if found {
		t.Errorf("found is true")
	}
}

func TestSegmentUInt64MapStop(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	m.Set(1, 100)

	// Stop is a no-op, should not panic
	m.Stop()

	// Map should still work after Stop
	val, found := m.Get(1)
	if !(found) {
		t.Errorf("found is false")
	}
	if !reflect.DeepEqual(100, val) {
		t.Errorf("val = %v, want %v", val, 100)
	}
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

	if !reflect.DeepEqual(5, count) {
		t.Errorf("count = %v, want %v", count, 5)
	}
}

func TestSegmentUInt64MapSegmentPowerBounds(t *testing.T) {
	// Test minimum segment power (should be clamped to 4)
	m1 := NewSegmentUInt64Map[int](1, 100)
	if !reflect.DeepEqual(16, m1.SegmentCount()) {
		t.Errorf("m1.SegmentCount() = %v, want %v", m1.SegmentCount(), 16)
	} // 2^4 = 16

	// Test maximum segment power (should be clamped to 8)
	m2 := NewSegmentUInt64Map[int](10, 100)
	if !reflect.DeepEqual(256, m2.SegmentCount()) {
		t.Errorf("m2.SegmentCount() = %v, want %v", m2.SegmentCount(), 256)
	} // 2^8 = 256

	// Test valid segment power
	m3 := NewSegmentUInt64Map[int](6, 100)
	if !reflect.DeepEqual(64, m3.SegmentCount()) {
		t.Errorf("m3.SegmentCount() = %v, want %v", m3.SegmentCount(), 64)
	} // 2^6 = 64
}

func TestSegmentUInt64MapClearSegmentOutOfBounds(t *testing.T) {
	m := NewSegmentUInt64Map[int](4, 100)

	m.Set(1, 100)

	// Clear with invalid index should not panic
	m.ClearSegment(-1)
	m.ClearSegment(1000)

	// Original value should still exist
	val, found := m.Get(1)
	if !(found) {
		t.Errorf("found is false")
	}
	if !reflect.DeepEqual(100, val) {
		t.Errorf("val = %v, want %v", val, 100)
	}
}
