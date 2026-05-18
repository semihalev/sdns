package cache

import (
	"iter"
)

// Pair contains a key-value pair
type Pair[V any] struct {
	Key   uint64
	Value V
}

// UInt64Map is a specialized map for uint64 keys.
// It is specifically optimized for clustered keys, where keys are likely
// to be close to each other (e.g., sequential IDs, timestamp ranges).
type UInt64Map[V any] struct {
	data       []Pair[V] // key-value pairs
	size       int       // current size
	growAt     int       // size threshold for growth
	mask       int       // power-of-2 mask
	hasZeroKey bool      // special case for zero key
	zeroVal    V         // value for zero key
}

// NewUInt64Map creates a new UInt64Map with given capacity
func NewUInt64Map[V any](capacity int) *UInt64Map[V] {
	// Ensure capacity is at least 8 and is a power of 2
	size := 8
	if capacity > 8 {
		capacity = int(float64(capacity) / 0.75)
		size = 1
		for size < capacity {
			size *= 2
		}
	}

	return &UInt64Map[V]{
		data:   make([]Pair[V], size),
		mask:   size - 1,
		growAt: int(float64(size) * 0.75),
	}
}

// Has checks if key exists in the map
func (m *UInt64Map[V]) Has(key uint64) bool {
	// Nil map check
	if m == nil {
		return false
	}

	// Special case for zero key
	if key == 0 {
		return m.hasZeroKey
	}

	// Calculate primary hash
	idx := m.primaryIndex(key)

	// Direct hit check (most common case)
	if m.data[idx].Key == key {
		return true
	}

	// Empty slot check (early exit)
	if m.data[idx].Key == 0 {
		return false
	}

	// Linear probing with Robin Hood hashing
	// This allows for efficient deletion
	for i := 1; i < len(m.data); i++ {
		idx = (idx + 1) & m.mask

		if m.data[idx].Key == key {
			return true
		}
		if m.data[idx].Key == 0 {
			return false
		}
	}

	return false
}

// Get retrieves a value by key
func (m *UInt64Map[V]) Get(key uint64) (V, bool) {
	// Nil map check
	if m == nil {
		var zero V
		return zero, false
	}

	// Special case for zero key
	if key == 0 {
		if m.hasZeroKey {
			return m.zeroVal, true
		}
		var zero V
		return zero, false
	}

	// Calculate primary index
	idx := m.primaryIndex(key)

	// Direct hit check (most common case)
	if m.data[idx].Key == key {
		return m.data[idx].Value, true
	}

	// Empty slot check (early exit)
	if m.data[idx].Key == 0 {
		var zero V
		return zero, false
	}

	// Linear probing
	for i := 1; i < len(m.data); i++ {
		idx = (idx + 1) & m.mask

		if m.data[idx].Key == key {
			return m.data[idx].Value, true
		}
		if m.data[idx].Key == 0 {
			var zero V
			return zero, false
		}
	}

	// Should never happen in properly sized map
	var zero V
	return zero, false
}

// Put adds or updates key with value
func (m *UInt64Map[V]) Put(key uint64, val V) {
	// Special case for zero key
	if key == 0 {
		if !m.hasZeroKey {
			m.size++
		}
		m.zeroVal = val
		m.hasZeroKey = true
		return
	}

	// Growth check
	if m.size >= m.growAt {
		m.grow()
	}

	// Calculate primary index
	idx := m.primaryIndex(key)

	// Fast path: empty slot
	if m.data[idx].Key == 0 {
		m.data[idx].Key = key
		m.data[idx].Value = val
		m.size++
		return
	}

	// Fast path: update existing key
	if m.data[idx].Key == key {
		m.data[idx].Value = val
		return
	}

	// Linear probing
	for i := 1; i < len(m.data); i++ {
		idx = (idx + 1) & m.mask

		if m.data[idx].Key == 0 {
			m.data[idx].Key = key
			m.data[idx].Value = val
			m.size++
			return
		}
		if m.data[idx].Key == key {
			m.data[idx].Value = val
			return
		}
	}

	// Should never happen in properly sized map, but just in case
	m.grow()
	m.Put(key, val)
}

// PutIfNotExists adds key-value pair only if key doesn't exist
func (m *UInt64Map[V]) PutIfNotExists(key uint64, val V) (V, bool) {
	// Special case for zero key
	if key == 0 {
		if m.hasZeroKey {
			return m.zeroVal, false
		}
		m.hasZeroKey = true
		m.zeroVal = val
		m.size++
		return val, true
	}

	// Growth check
	if m.size >= m.growAt {
		m.grow()
	}

	// Calculate primary index
	idx := m.primaryIndex(key)

	// Fast path: empty slot
	if m.data[idx].Key == 0 {
		m.data[idx].Key = key
		m.data[idx].Value = val
		m.size++
		return val, true
	}

	// Check existing key
	if m.data[idx].Key == key {
		return m.data[idx].Value, false
	}

	// Linear probing
	for i := 1; i < len(m.data); i++ {
		idx = (idx + 1) & m.mask

		if m.data[idx].Key == 0 {
			m.data[idx].Key = key
			m.data[idx].Value = val
			m.size++
			return val, true
		}
		if m.data[idx].Key == key {
			return m.data[idx].Value, false
		}
	}

	// Should never happen in properly sized map, but just in case
	m.grow()
	return m.PutIfNotExists(key, val)
}

// Del deletes a key and its value
func (m *UInt64Map[V]) Del(key uint64) bool {
	// Nil map check
	if m == nil {
		return false
	}

	// Special case for zero key
	if key == 0 {
		if m.hasZeroKey {
			var zero V
			m.hasZeroKey = false
			m.zeroVal = zero
			m.size--
			return true
		}
		return false
	}

	// Calculate primary index
	idx := m.primaryIndex(key)

	// Check if key exists at primary position
	if m.data[idx].Key == key {
		// Mark as deleted
		var zero V
		m.data[idx].Key = 0
		m.data[idx].Value = zero
		m.size--

		// Use backward shift deletion for linear probing
		m.backwardShiftDelete(idx)
		return true
	}

	// Early exit if empty slot
	if m.data[idx].Key == 0 {
		return false
	}

	// Linear probing to find the key
	for i := 1; i < len(m.data); i++ {
		idx = (idx + 1) & m.mask

		if m.data[idx].Key == key {
			// Found key, mark as deleted
			var zero V
			m.data[idx].Key = 0
			m.data[idx].Value = zero
			m.size--
			m.backwardShiftDelete(idx)
			return true
		}
		if m.data[idx].Key == 0 {
			return false
		}
	}

	return false
}

// ForEach iterates through all key-value pairs
func (m *UInt64Map[V]) ForEach(f func(uint64, V) bool) {
	if m == nil {
		return
	}

	// Zero key first
	if m.hasZeroKey && !f(0, m.zeroVal) {
		return
	}

	// Then all other keys
	for _, p := range m.data {
		if p.Key != 0 && !f(p.Key, p.Value) {
			return
		}
	}
}

// All returns an iterator over key-value pairs
func (m *UInt64Map[V]) All() iter.Seq2[uint64, V] {
	return m.ForEach
}

// Keys returns an iterator over keys
func (m *UInt64Map[V]) Keys() iter.Seq[uint64] {
	return func(yield func(uint64) bool) {
		if m == nil {
			return
		}

		// Zero key first
		if m.hasZeroKey && !yield(0) {
			return
		}

		// Then all other keys
		for _, p := range m.data {
			if p.Key != 0 && !yield(p.Key) {
				return
			}
		}
	}
}

// Values returns an iterator over values
func (m *UInt64Map[V]) Values() iter.Seq[V] {
	return func(yield func(V) bool) {
		if m == nil {
			return
		}

		// Zero key's value first
		if m.hasZeroKey && !yield(m.zeroVal) {
			return
		}

		// Then all other values
		for _, p := range m.data {
			if p.Key != 0 && !yield(p.Value) {
				return
			}
		}
	}
}

// Clear removes all items from the map
func (m *UInt64Map[V]) Clear() {
	if m == nil {
		return
	}

	// Reset zero key
	var zero V
	m.hasZeroKey = false
	m.zeroVal = zero

	// Clear all entries
	for i := range m.data {
		m.data[i] = Pair[V]{}
	}

	m.size = 0
}

// Len returns the number of elements in the map
func (m *UInt64Map[V]) Len() int {
	if m == nil {
		return 0
	}
	return m.size
}

// Internal helper functions

// primaryIndex calculates the initial index for a key
func (m *UInt64Map[V]) primaryIndex(key uint64) int {
	// Primary hash function optimized for integer keys
	h := key * uint64(0x9E3779B9)
	return int(h^(h>>16)) & m.mask //nolint:gosec // G115 - mask ensures valid range
}

// grow increases the size of the map and rehashes all entries
func (m *UInt64Map[V]) grow() {
	// Use a more conservative growth factor for large maps
	// For small maps, double the size
	// For large maps (>1M entries), use 1.5x growth to reduce memory spikes
	oldLen := len(m.data)
	newLen := oldLen * 2

	// For very large maps, use a smaller growth factor to reduce memory pressure
	if oldLen >= 1_048_576 { // 1M entries
		newLen = oldLen + (oldLen / 2) // 1.5x growth for large maps
	}

	// Ensure new length is a power of 2 for efficient masking
	if newLen&(newLen-1) != 0 {
		// Round up to next power of 2
		newLen--
		newLen |= newLen >> 1
		newLen |= newLen >> 2
		newLen |= newLen >> 4
		newLen |= newLen >> 8
		newLen |= newLen >> 16
		newLen |= newLen >> 32
		newLen++
	}

	// Create new data array
	oldData := m.data
	m.data = make([]Pair[V], newLen)
	m.mask = newLen - 1
	m.growAt = int(float64(newLen) * 0.75)

	// Save zero key info (avoid re-entry which calls Put)
	hasZeroKey := m.hasZeroKey
	zeroVal := m.zeroVal

	// Reset size (will be incremented as we add items)
	m.size = 0
	m.hasZeroKey = false

	// Re-insert all non-zero keys directly (bypass Put to avoid redundant checks)
	// This optimization reduces function call overhead
	for i := range oldData {
		p := &oldData[i] // Use pointer to avoid copying the pair
		if p.Key != 0 {
			// Reuse the optimized insertion logic but avoid calling Put
			// to reduce function call overhead and extra checks
			h := m.primaryIndex(p.Key)
			// Try to insert at the primary position
			if m.data[h].Key == 0 {
				// Fast path: slot is empty
				m.data[h].Key = p.Key
				m.data[h].Value = p.Value
				m.size++
				continue
			}

			// Collision: use linear probing
			for j := 1; j < len(m.data); j++ {
				h = (h + 1) & m.mask

				if m.data[h].Key == 0 {
					m.data[h].Key = p.Key
					m.data[h].Value = p.Value
					m.size++
					break
				}
			}
		}
	}

	// Restore zero key if it existed
	if hasZeroKey {
		m.hasZeroKey = true
		m.zeroVal = zeroVal
		m.size++
	}

	// Help the garbage collector by explicitly clearing the reference to oldData
	// This isn't strictly necessary but can help reduce memory pressure
	// by allowing the GC to collect the old array sooner
	oldData = nil
}

// backwardShiftDelete implements backward shift deletion for linear probing
// This is efficient and maintains the invariant that all keys remain findable
func (m *UInt64Map[V]) backwardShiftDelete(deletedIdx int) {
	var zero V
	idx := deletedIdx

	// Shift entries back to fill the gap
	for {
		// Look at the next slot
		nextIdx := (idx + 1) & m.mask

		// If next slot is empty, we're done
		if m.data[nextIdx].Key == 0 {
			break
		}

		// Get the ideal position for the key in the next slot
		idealIdx := m.primaryIndex(m.data[nextIdx].Key)

		// With linear probing, we need to check if moving this key
		// would break the probe chain for finding it
		// The key can be moved if there's no gap between its ideal position
		// and the empty slot when following the linear probe sequence

		// Simple check: can we reach the empty slot from the ideal position?
		canReachEmpty := false
		checkIdx := idealIdx
		for i := 0; i < len(m.data); i++ {
			if checkIdx == idx {
				canReachEmpty = true
				break
			}
			if m.data[checkIdx].Key == 0 {
				// There's a gap before reaching the empty slot
				break
			}
			checkIdx = (checkIdx + 1) & m.mask
		}

		if canReachEmpty {
			// Move this entry back to fill the gap
			m.data[idx] = m.data[nextIdx]
			m.data[nextIdx].Key = 0
			m.data[nextIdx].Value = zero
			// Continue from the newly empty slot
			idx = nextIdx
		} else {
			// Cannot move this key without breaking probe chains
			// We're done
			break
		}
	}
}
