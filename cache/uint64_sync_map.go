package cache

import (
	"iter"
	"unsafe"
)

// SyncUInt64Map wraps SegmentUInt64Map to provide the expected interface
type SyncUInt64Map[V any] struct {
	data *SegmentUInt64Map[V]
}

// NewSyncUInt64Map creates a new map
func NewSyncUInt64Map[V any](sizePower uint) *SyncUInt64Map[V] {
	// Use segment power of 8 as mentioned (256 segments)
	segmentPower := uint8(8)

	// Calculate initial capacity from sizePower
	initialCapacity := 1 << sizePower

	return &SyncUInt64Map[V]{
		data: NewSegmentUInt64Map[V](segmentPower, initialCapacity),
	}
}

// Get retrieves a value by key
func (m *SyncUInt64Map[V]) Get(key uint64) (V, bool) {
	return m.data.Get(key)
}

// Set adds or updates a key-value pair
func (m *SyncUInt64Map[V]) Set(key uint64, value V) {
	m.data.Set(key, value)
}

// Del removes a key from the map
func (m *SyncUInt64Map[V]) Del(key uint64) bool {
	return m.data.Del(key)
}

// Has checks if a key exists
func (m *SyncUInt64Map[V]) Has(key uint64) bool {
	return m.data.Has(key)
}

// Len returns the number of entries
func (m *SyncUInt64Map[V]) Len() int64 {
	return m.data.Len()
}

// ForEach iterates over all entries
func (m *SyncUInt64Map[V]) ForEach(f func(uint64, V) bool) {
	m.data.ForEach(f)
}

// All returns an iterator
func (m *SyncUInt64Map[V]) All() iter.Seq2[uint64, V] {
	return m.ForEach
}

// RandomSample returns a random sample of keys
func (m *SyncUInt64Map[V]) RandomSample(maxSample int) []uint64 {
	if maxSample <= 0 {
		return nil
	}

	// For better randomness, sample from different segments
	result := make([]uint64, 0, maxSample)
	segments := m.data.segments
	numSegments := len(segments)

	// Start from a random segment
	startIdx := int(uint64(uintptr(unsafe.Pointer(&result))) % uint64(numSegments)) //nolint:gosec // G103 G115 - using pointer address for randomization

	// Sample across segments round-robin
	for i := 0; i < numSegments && len(result) < maxSample; i++ {
		segIdx := (startIdx + i) % numSegments
		segment := segments[segIdx]

		// Lock segment for sampling
		segment.rwlock.RLock()

		// Sample a few keys from this segment
		sampled := 0
		maxFromSegment := (maxSample / numSegments) + 1

		segment.data.ForEach(func(key uint64, _ V) bool {
			if sampled >= maxFromSegment || len(result) >= maxSample {
				return false
			}
			result = append(result, key)
			sampled++
			return true
		})

		segment.rwlock.RUnlock()
	}

	return result
}

// Compact is a no-op for this implementation as it handles memory efficiently
func (m *SyncUInt64Map[V]) Compact() int {
	// This implementation doesn't accumulate deleted entries
	// so there's nothing to compact
	return 0
}

// Stop is a no-op for compatibility
func (m *SyncUInt64Map[V]) Stop() {
	// Nothing to stop
}

// Clear removes all entries - FAST!
func (m *SyncUInt64Map[V]) Clear() {
	m.data.Clear()
}

// ClearSegment clears a specific segment - for radical eviction
func (m *SyncUInt64Map[V]) ClearSegment(index int) {
	m.data.ClearSegment(index)
}

// SegmentCount returns the number of segments
func (m *SyncUInt64Map[V]) SegmentCount() int {
	return m.data.SegmentCount()
}
