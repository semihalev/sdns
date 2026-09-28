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
//
// V is the stored value type, a pointer in every user. A concrete V keeps
// each slot at two words, where an interface value would take three.
type Cache[V comparable] struct {
	data    *SyncUInt64Map[V]
	maxSize int64
}

// New creates a bounded cache.
func New[V comparable](size int) *Cache[V] {
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

	return &Cache[V]{
		data:    NewSyncUInt64Map[V](power),
		maxSize: int64(size),
	}
}

// Get retrieves a value - uses SyncUInt64Map's excellent performance
func (c *Cache[V]) Get(key uint64) (V, bool) {
	return c.data.Get(key)
}

// Add adds an item; an over-capacity insert self-evicts up to two entries
// from its own segment, so occupancy is bounded at any write rate while
// per-Add work stays a small constant.
func (c *Cache[V]) Add(key uint64, value V) {
	c.data.SetWithCap(key, value, c.maxSize)
}

// Remove removes an item
func (c *Cache[V]) Remove(key uint64) {
	c.data.Del(key)
}

// AddIfAbsent adds the item only if the key is not already present, paying
// the same self-eviction toll as Add when the insert pushes the map over
// capacity. The existence check and the insert run under the key's segment
// write lock, so a concurrent Add cannot land between them. Returns whether
// value was stored.
func (c *Cache[V]) AddIfAbsent(key uint64, value V) bool {
	return c.data.data.PutIfNotExistsWithCap(key, value, c.maxSize)
}

// CompareAndSwap stores value under key only if the value currently
// stored is identical (==, i.e. pointer identity for pointer-typed
// values) to old. Returns false, storing nothing, when the key is
// absent or holds a different value. The check-and-set runs under the
// key's segment write lock, so a concurrent Add/Remove cannot
// interleave between the compare and the swap.
//
// This is the late-write guard for asynchronous refreshes
// (GHSA-mqfw-f48p-2vc8): a stale in-flight result may only replace
// the exact entry it set out to refresh, never state that landed
// after it started.
func (c *Cache[V]) CompareAndSwap(key uint64, old, value V) bool {
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
func (c *Cache[V]) CompareAndDelete(key uint64, old V) bool {
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
func (c *Cache[V]) Len() int {
	return int(c.data.Len())
}

// Stop cleanup
func (c *Cache[V]) Stop() {
	c.data.Stop()
}

// ForEach iterates over all cache entries.
// Iteration is not atomic with concurrent updates.
func (c *Cache[V]) ForEach(f func(key uint64, value V) bool) {
	c.data.ForEach(f)
}

// PruneChunk is the most slots one Prune step examines, and the most it
// removes, under one hold of a segment lock.
const PruneChunk = 64

// PruneCursor is where the next Prune step resumes. The zero value starts
// a pass at the first segment.
type PruneCursor struct {
	seg, slot int
}

// Prune takes one step of a background sweep: it examines up to
// PruneChunk slots of one segment from the cursor, under that segment's
// read lock, for the values dead reports, then, under its write lock,
// removes each one still stored that take accepts (a newer value is left
// alone). No lock is held between steps, so a sweep paced by its caller
// keeps a reader or a writer waiting for one step's work at most: the
// read-locked scan of the slots, and under the write lock up to
// PruneChunk removals, each with the probe-chain shift a removal makes.
//
// dead and take run under the segment lock: they must be quick and must
// not touch this cache. dead only selects, under the read lock; take is
// the decision, under the write lock, and may claim the value, so that
// something racing to use it either wins before the removal or sees the
// claim. The sweep is best effort. Removals and growth move values between
// slots while it runs, so a pass can miss a value or see one twice, and
// the next pass takes what this one missed. passDone reports that this
// step finished the last segment and the cursor starts over.
func (c *Cache[V]) Prune(cur *PruneCursor, dead, take func(V) bool) (removed int, passDone bool) {
	m := c.data.data
	if cur.seg >= len(m.segments) {
		cur.seg, cur.slot = 0, 0
	}
	seg := m.segments[cur.seg]

	var (
		keys [PruneChunk]uint64
		vals [PruneChunk]V
		n    int
	)
	seg.rwlock.RLock()
	data := seg.data.data
	end := min(cur.slot+PruneChunk, len(data))
	for i := cur.slot; i < end; i++ {
		if p := data[i]; p.Key != 0 && dead(p.Value) {
			keys[n], vals[n] = p.Key, p.Value
			n++
		}
	}
	segDone := end >= len(data)
	seg.rwlock.RUnlock()

	if n > 0 {
		seg.rwlock.Lock()
		for i := range n {
			if v, ok := seg.data.Get(keys[i]); ok && v == vals[i] && take(v) && seg.data.Del(keys[i]) {
				removed++
			}
		}
		seg.rwlock.Unlock()
		m.count.Add(int64(-removed))
	}

	if !segDone {
		cur.slot = end
		return removed, false
	}
	cur.seg, cur.slot = cur.seg+1, 0
	if cur.seg >= len(m.segments) {
		cur.seg = 0
		return removed, true
	}
	return removed, false
}
