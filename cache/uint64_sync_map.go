package cache

import (
	"iter"
	"math/bits"
	"math/rand/v2"
	"sync/atomic"
	"unsafe"
)

// SyncUInt64Map syncUInt64Map: lock-free hash map using CAS operations on linked lists.
type SyncUInt64Map[V any] struct {
	buckets []bucket[V]
	mask    uint64
	count   atomic.Int64
}

type bucket[V any] struct {
	head unsafe.Pointer // *fnode[V]
}

type fnode[V any] struct {
	key     uint64
	value   atomic.Pointer[V]
	next    unsafe.Pointer // *fnode[V]
	deleted uint32
}

// NewSyncUInt64Map creates a new optimized map for uint64 keys.
func NewSyncUInt64Map[V any](sizePower uint) *SyncUInt64Map[V] {
	if sizePower < 2 {
		sizePower = 2 // Minimum 4 buckets
	}

	size := uint64(1 << sizePower)
	mask := size - 1

	// Create buckets
	buckets := make([]bucket[V], size)

	return &SyncUInt64Map[V]{
		buckets: buckets,
		mask:    mask,
	}
}

// hashFast: avalanche mixing spreads bits for uniform bucket distribution.
func hashFast(key uint64) uint64 {
	key *= 0xd6e8feb86659fd93
	key = bits.RotateLeft64(key, 32) ^ key

	return key
}

// ().Get get retrieves a value by key.
func (m *SyncUInt64Map[V]) Get(key uint64) (V, bool) {
	hash := hashFast(key)
	bucket := &m.buckets[hash&m.mask]

	// Search in the linked list
	for node := (*fnode[V])(atomic.LoadPointer(&bucket.head)); node != nil; node = (*fnode[V])(atomic.LoadPointer(&node.next)) {

		if node.key == key && atomic.LoadUint32(&node.deleted) == 0 {
			value := node.value.Load()
			if value != nil {
				return *value, true
			}
			break
		}
	}

	var zero V
	return zero, false
}

// ().Set set adds or updates a key-value pair.
func (m *SyncUInt64Map[V]) Set(key uint64, value V) {
	hash := hashFast(key)
	bucket := &m.buckets[hash&m.mask]

retry:
	// First check if the key already exists
	var predecessor *fnode[V]
	var current *fnode[V]

	// Load the head of the list
	head := (*fnode[V])(atomic.LoadPointer(&bucket.head))

	// Check if the key exists
	for current = head; current != nil; {
		if current.key == key {
			// Key exists, just update value
			current.value.Store(&value)

			// If it was deleted, resurrect it
			if atomic.LoadUint32(&current.deleted) == 1 {
				if atomic.CompareAndSwapUint32(&current.deleted, 1, 0) {
					m.count.Add(1)
				}
			}
			return
		}

		predecessor = current
		current = (*fnode[V])(atomic.LoadPointer(&current.next))
	}

	// Key doesn't exist, create a new node
	newNode := &fnode[V]{
		key: key,
	}
	newNode.value.Store(&value)

	// Insert at head if first node or predecessor is nil
	if head == nil || predecessor == nil {
		for {
			// Load the current head
			currentHead := (*fnode[V])(atomic.LoadPointer(&bucket.head))

			// Set the new node's next pointer to the current head
			atomic.StorePointer(&newNode.next, unsafe.Pointer(currentHead))

			// Try to set the new node as the new head
			if atomic.CompareAndSwapPointer(&bucket.head, unsafe.Pointer(currentHead), unsafe.Pointer(newNode)) {
				// Successfully inserted, increment counter
				m.count.Add(1)
				return
			}

			// CAS failed, retry from beginning to check if key was inserted
			// by another thread. We must restart from the beginning to ensure
			// we don't miss any concurrent insertions.
			goto retry
		}
	} else {
		// Insert after predecessor
		for {
			// Load predecessor's next
			next := (*fnode[V])(atomic.LoadPointer(&predecessor.next))

			// Set new node's next
			atomic.StorePointer(&newNode.next, unsafe.Pointer(next))

			// Try to set predecessor's next to the new node
			if atomic.CompareAndSwapPointer(&predecessor.next, unsafe.Pointer(next), unsafe.Pointer(newNode)) {
				// Successfully inserted, increment counter
				m.count.Add(1)
				return
			}

			// CAS failed, check if the key was inserted by another thread
			// or if the predecessor is still valid
			current = (*fnode[V])(atomic.LoadPointer(&bucket.head))
			var found bool
			for current != nil {
				if current == predecessor {
					found = true
					// Predecessor still exists, check its next nodes
					current = (*fnode[V])(atomic.LoadPointer(&current.next))
					for current != nil {
						if current.key == key {
							if atomic.LoadUint32(&current.deleted) == 0 {
								current.value.Store(&value)
								return
							}
							// Key exists but is deleted, retry from beginning
							goto retry
						}
						current = (*fnode[V])(atomic.LoadPointer(&current.next))
					}
					// Key not found after predecessor, continue trying to insert
					break
				}
				current = (*fnode[V])(atomic.LoadPointer(&current.next))
			}

			if !found {
				// Predecessor no longer in the list, retry from beginning
				goto retry
			}
		}
	}
}

// ().Del del removes a key from the map.
func (m *SyncUInt64Map[V]) Del(key uint64) bool {
	hash := hashFast(key)
	bucket := &m.buckets[hash&m.mask]

	// Search for the key
	for node := (*fnode[V])(atomic.LoadPointer(&bucket.head)); node != nil; node = (*fnode[V])(atomic.LoadPointer(&node.next)) {

		if node.key == key && atomic.LoadUint32(&node.deleted) == 0 {
			// Found non-deleted node with matching key
			if atomic.CompareAndSwapUint32(&node.deleted, 0, 1) {
				// Successfully marked as deleted
				m.count.Add(-1)
				return true
			}
			// If CAS failed, someone else deleted it or resurrected it
			return false
		}
	}

	// Key not found or already deleted
	return false
}

// CompactBucket rebuilds a bucket, removing deleted nodes.
// This helps prevent memory leaks from deleted nodes.
func (m *SyncUInt64Map[V]) CompactBucket(bucketIdx int) int {
	if bucketIdx < 0 || bucketIdx >= len(m.buckets) {
		return 0
	}

	bucket := &m.buckets[bucketIdx]
	cleaned := 0

	// Build new chain with only non-deleted nodes
	var newHead *fnode[V]
	var newTail *fnode[V]

	// Traverse the existing chain
	for node := (*fnode[V])(atomic.LoadPointer(&bucket.head)); node != nil; node = (*fnode[V])(atomic.LoadPointer(&node.next)) {
		if atomic.LoadUint32(&node.deleted) == 0 {
			// Node is active, add to new chain
			newNode := &fnode[V]{
				key: node.key,
			}
			value := node.value.Load()
			newNode.value.Store(value)

			if newHead == nil {
				newHead = newNode
				newTail = newNode
			} else {
				newTail.next = unsafe.Pointer(newNode)
				newTail = newNode
			}
		} else {
			cleaned++
		}
	}

	// Atomically replace the bucket head
	atomic.StorePointer(&bucket.head, unsafe.Pointer(newHead))

	return cleaned
}

// Compact removes all deleted nodes from the map.
// This should be called periodically to prevent memory leaks.
func (m *SyncUInt64Map[V]) Compact() int {
	totalCleaned := 0

	// Compact each bucket
	for i := range m.buckets {
		totalCleaned += m.CompactBucket(i)
	}

	return totalCleaned
}

// ().Len len returns the number of elements in the map.
func (m *SyncUInt64Map[V]) Len() int64 {
	return m.count.Load()
}

func (m *SyncUInt64Map[V]) All() iter.Seq2[uint64, V] {
	return m.ForEach
}

// ().ForEach forEach iterates through all key-value pairs.
func (m *SyncUInt64Map[V]) ForEach(f func(uint64, V) bool) {
	// For each bucket
	for i := range m.buckets {
		// Get the bucket
		bucket := &m.buckets[i]

		// Iterate through the linked list
		for node := (*fnode[V])(atomic.LoadPointer(&bucket.head)); node != nil; node = (*fnode[V])(atomic.LoadPointer(&node.next)) {

			// Skip deleted nodes
			if atomic.LoadUint32(&node.deleted) != 0 {
				continue
			}

			// Get value
			value := node.value.Load()
			if value == nil {
				continue
			}

			// Call the function
			if !f(node.key, *value) {
				return
			}
		}
	}
}

// ().Has has checks if a key exists in the map without retrieving its value.
func (m *SyncUInt64Map[V]) Has(key uint64) bool {
	hash := hashFast(key)
	bucket := &m.buckets[hash&m.mask]

	// Search in the linked list
	for node := (*fnode[V])(atomic.LoadPointer(&bucket.head)); node != nil; node = (*fnode[V])(atomic.LoadPointer(&node.next)) {
		if node.key == key && atomic.LoadUint32(&node.deleted) == 0 {
			// Found non-deleted node with matching key
			return true
		}
	}

	return false
}

// ().RandomSample randomSample: O(sample) complexity by sampling random buckets, not full scan.
func (m *SyncUInt64Map[V]) RandomSample(maxSample int) []uint64 {
	if maxSample <= 0 {
		return nil
	}

	numBuckets := len(m.buckets)
	if numBuckets == 0 {
		return nil
	}

	// Pre-allocate result slice
	result := make([]uint64, 0, maxSample)

	// Sample 2x buckets to account for sparse/uneven distribution
	bucketsToSample := maxSample * 2
	if bucketsToSample > numBuckets {
		bucketsToSample = numBuckets
	}

	// Use map to track sampled buckets and avoid duplicates
	sampledBuckets := make(map[int]struct{}, bucketsToSample)

	// Sample random buckets until we have enough keys or sampled enough buckets
	for len(sampledBuckets) < bucketsToSample && len(result) < maxSample {
		// Pick a random bucket
		bucketIdx := rand.IntN(numBuckets)

		// Skip if already sampled
		if _, exists := sampledBuckets[bucketIdx]; exists {
			continue
		}
		sampledBuckets[bucketIdx] = struct{}{}

		bucket := &m.buckets[bucketIdx]

		// Collect keys from this bucket
		for node := (*fnode[V])(atomic.LoadPointer(&bucket.head)); node != nil && len(result) < maxSample; node = (*fnode[V])(atomic.LoadPointer(&node.next)) {
			// Skip deleted nodes
			if atomic.LoadUint32(&node.deleted) != 0 {
				continue
			}

			// Add key to result
			result = append(result, node.key)
		}
	}

	return result
}
