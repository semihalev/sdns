package cache

import (
	"iter"
	"sync"
	"sync/atomic"
)

// SegmentUInt64Map is a fast, thread-safe map for int64 keys
// that uses sharding (segmentation) to reduce lock contention
// while maintaining the performance benefits of UInt64Map
type SegmentUInt64Map[V any] struct {
	segments    []*segment[V]
	segmentMask int
	segmentBits uint8
	count       atomic.Int64
}

// segment is a single shard of the map
type segment[V any] struct {
	data   *UInt64Map[V] // Use the optimized UInt64Map internally
	rwlock sync.RWMutex  // RWMutex for fine-grained locking
}

// NewSegmentUInt64Map creates a new segmented map for int64 keys
// segmentPower controls the number of segments (2^segmentPower)
// initialCapacity is the initial capacity per segment
func NewSegmentUInt64Map[V any](segmentPower uint8, initialCapacity int) *SegmentUInt64Map[V] {
	// Ensure segment power is at least 4 (16 segments) and at most 8 (256 segments)
	if segmentPower < 4 {
		segmentPower = 4 // Minimum 16 segments
	} else if segmentPower > 8 {
		segmentPower = 8 // Maximum 256 segments
	}

	segmentCount := 1 << segmentPower
	segmentMask := segmentCount - 1

	// Calculate per-segment capacity
	segmentCapacity := initialCapacity / segmentCount
	if segmentCapacity < 8 {
		segmentCapacity = 8 // Minimum per-segment capacity
	}

	// Create segments
	segments := make([]*segment[V], segmentCount)
	for i := 0; i < segmentCount; i++ {
		segments[i] = &segment[V]{
			data: NewUInt64Map[V](segmentCapacity),
		}
	}

	return &SegmentUInt64Map[V]{
		segments:    segments,
		segmentMask: segmentMask,
		segmentBits: segmentPower,
		// count is initialized to 0 by default
	}
}

// getSegment returns the segment for a given key
func (m *SegmentUInt64Map[V]) getSegment(key uint64) *segment[V] {
	// Use the high bits of the hash as segment index
	// This distributes sequential keys across different segments
	// and reduces contention for clustered keys
	h := uint(key * 0x9E3779B9)
	segmentIndex := (h >> 16) & uint(m.segmentMask)
	return m.segments[segmentIndex]
}

// Has checks if a key exists in the map
func (m *SegmentUInt64Map[V]) Has(key uint64) bool {
	segment := m.getSegment(key)
	segment.rwlock.RLock()
	defer segment.rwlock.RUnlock()
	return segment.data.Has(key)
}

// Get retrieves a value by key
func (m *SegmentUInt64Map[V]) Get(key uint64) (V, bool) {
	segment := m.getSegment(key)
	segment.rwlock.RLock()
	defer segment.rwlock.RUnlock()
	return segment.data.Get(key)
}

// Set adds or updates a key-value pair
func (m *SegmentUInt64Map[V]) Set(key uint64, value V) {
	segment := m.getSegment(key)
	segment.rwlock.Lock()
	defer segment.rwlock.Unlock()

	// Get the old size to check if we added a new key
	oldSize := segment.data.Len()
	segment.data.Put(key, value)
	newSize := segment.data.Len()

	// Only increment count if size increased (new key was added)
	if newSize > oldSize {
		m.count.Add(1)
	}
}

// PutIfNotExists adds the key-value pair only if the key doesn't already exist
// Returns the value and true if inserted, or existing value and false if not inserted
func (m *SegmentUInt64Map[V]) PutIfNotExists(key uint64, value V) (V, bool) {
	segment := m.getSegment(key)
	segment.rwlock.Lock()
	defer segment.rwlock.Unlock()

	result, inserted := segment.data.PutIfNotExists(key, value)
	if inserted {
		m.count.Add(1)
	}
	return result, inserted
}

// Del removes a key from the map
func (m *SegmentUInt64Map[V]) Del(key uint64) bool {
	segment := m.getSegment(key)
	segment.rwlock.Lock()
	defer segment.rwlock.Unlock()

	deleted := segment.data.Del(key)
	if deleted {
		m.count.Add(-1)
	}
	return deleted
}

// Len returns the number of elements in the map
func (m *SegmentUInt64Map[V]) Len() int64 {
	return m.count.Load()
}

// ForEach iterates through all key-value pairs
// Note: The iteration is not atomic and may miss concurrent updates
func (m *SegmentUInt64Map[V]) ForEach(f func(uint64, V) bool) {
	// For each segment
	for _, segment := range m.segments {
		// Lock segment for reading
		segment.rwlock.RLock()

		// Create a copy of the callback to avoid capturing the loop variable
		callback := f
		continueIteration := true

		// Use the segment's map ForEach with a wrapper that manages continuation
		segment.data.ForEach(func(key uint64, value V) bool {
			result := callback(key, value)
			if !result {
				continueIteration = false
			}
			return result
		})

		// Unlock segment
		segment.rwlock.RUnlock()

		// Check if we should stop iteration
		if !continueIteration {
			break
		}
	}
}

// All returns an iterator over all key-value pairs
func (m *SegmentUInt64Map[V]) All() iter.Seq2[uint64, V] {
	return m.ForEach
}

// Keys returns an iterator over all keys
func (m *SegmentUInt64Map[V]) Keys() iter.Seq[uint64] {
	return func(yield func(uint64) bool) {
		m.ForEach(func(key uint64, _ V) bool {
			return yield(key)
		})
	}
}

// Values returns an iterator over all values
func (m *SegmentUInt64Map[V]) Values() iter.Seq[V] {
	return func(yield func(V) bool) {
		m.ForEach(func(_ uint64, value V) bool {
			return yield(value)
		})
	}
}

// Clear removes all entries from the map
func (m *SegmentUInt64Map[V]) Clear() {
	// For each segment
	for _, segment := range m.segments {
		segment.rwlock.Lock()
		segment.data.Clear()
		segment.rwlock.Unlock()
	}

	// Reset count
	m.count.Store(0)
}

// ClearSegment clears a specific segment - for radical eviction
func (m *SegmentUInt64Map[V]) ClearSegment(index int) {
	if index < 0 || index >= len(m.segments) {
		return
	}

	segment := m.segments[index]
	segment.rwlock.Lock()

	// Count items before clearing to update total count
	itemsCleared := int64(segment.data.Len())
	segment.data.Clear()

	segment.rwlock.Unlock()

	// Update total count
	m.count.Add(-itemsCleared)
}

// SegmentCount returns the number of segments
func (m *SegmentUInt64Map[V]) SegmentCount() int {
	return len(m.segments)
}

// Stop is a no-op for compatibility
func (m *SegmentUInt64Map[V]) Stop() {
	// Nothing to stop
}
