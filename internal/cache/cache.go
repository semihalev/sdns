package cache

import (
	"errors"
)

var (
	// ErrCacheNotFound error.
	ErrCacheNotFound = errors.New("cache not found")
	// ErrCacheExpired error.
	ErrCacheExpired = errors.New("cache expired")
)

// Cache is a bounded concurrent map with proportional random eviction:
// an over-capacity insert evicts up to two entries from the segment it
// already holds the write lock for. No bulk clearing, no dedicated
// evictor, no lock a writer could ever queue behind (2026-07-28 incident:
// 1.43M goroutines, 93% blocked behind cache segment locks while
// segment-clearing eviction dumped 10-60% of the glue cache mid-outage).
type Cache struct {
	data    *SyncUInt64Map[any]
	maxSize int64
}

// New creates a bounded cache.
func New(size int) *Cache {
	if size < 1 {
		size = 1
	}

	// Use optimal bucket sizing for SyncUInt64Map
	var power uint
	switch {
	case size <= 1024:
		power = 8 // 256 buckets
	case size <= 10000:
		power = 10 // 1K buckets
	case size <= 100000:
		power = 12 // 4K buckets
	case size <= 500000:
		power = 14 // 16K buckets
	default:
		power = 16 // 64K buckets for 1M+ entries
	}

	return &Cache{
		data:    NewSyncUInt64Map[any](power),
		maxSize: int64(size),
	}
}

// Get retrieves a value - uses SyncUInt64Map's excellent performance
func (c *Cache) Get(key uint64) (any, bool) {
	return c.data.Get(key)
}

// Add adds an item; an over-capacity insert self-evicts up to two entries
// from its own segment, so occupancy is bounded at any write rate while
// per-Add work stays a small constant.
func (c *Cache) Add(key uint64, value any) {
	c.data.SetWithCap(key, value, c.maxSize)
}

// Remove removes an item
func (c *Cache) Remove(key uint64) {
	c.data.Del(key)
}

// AddIfAbsent adds the item only if the key is not already present, paying
// the same self-eviction toll as Add when the insert pushes the map over
// capacity. The existence check and the insert run under the key's segment
// write lock, so a concurrent Add cannot land between them. Returns whether
// value was stored.
func (c *Cache) AddIfAbsent(key uint64, value any) bool {
	return c.data.data.PutIfNotExistsWithCap(key, value, c.maxSize)
}

// CompareAndSwap stores value under key only if the value currently
// stored is identical (==, i.e. pointer identity for pointer-typed
// values) to old. Returns false — storing nothing — when the key is
// absent or holds a different value. The check-and-set runs under the
// key's segment write lock, so a concurrent Add/Remove cannot
// interleave between the compare and the swap.
//
// This is the late-write guard for asynchronous refreshes
// (GHSA-mqfw-f48p-2vc8): a stale in-flight result may only replace
// the exact entry it set out to refresh, never state that landed
// after it started.
func (c *Cache) CompareAndSwap(key uint64, old, value any) bool {
	seg := c.data.data.getSegment(key)
	seg.rwlock.Lock()
	defer seg.rwlock.Unlock()

	cur, ok := seg.data.Get(key)
	if !ok || cur != old {
		return false
	}
	seg.data.Put(key, value)
	return true
}

// CompareAndDelete removes key only if its current value is identical to old.
// Expiry cleanup uses this instead of an unconditional Remove: a fresh value
// may be published after the reader loaded the expired entry, and that newer
// value must not be deleted by the stale reader.
func (c *Cache) CompareAndDelete(key uint64, old any) bool {
	seg := c.data.data.getSegment(key)
	seg.rwlock.Lock()
	defer seg.rwlock.Unlock()

	cur, ok := seg.data.Get(key)
	if !ok || cur != old {
		return false
	}
	if !seg.data.Del(key) {
		return false
	}
	c.data.data.count.Add(-1)
	return true
}

// Len returns current size
func (c *Cache) Len() int {
	return int(c.data.Len())
}

// Stop cleanup
func (c *Cache) Stop() {
	c.data.Stop()
}

// ForEach iterates over all cache entries.
// Iteration is not atomic with concurrent updates.
func (c *Cache) ForEach(f func(key uint64, value any) bool) {
	c.data.ForEach(f)
}
