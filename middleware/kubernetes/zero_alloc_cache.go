package kubernetes

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

// ZeroAllocCache - TRUE zero-allocation DNS cache
// This implementation achieves zero allocations by:
// 1. Pre-allocating all memory at initialization
// 2. Storing DNS messages in wire format only
// 3. Using fixed-size buffers and entries
// 4. Returning direct references to cached data
type ZeroAllocCache struct {
	// Pre-allocated entries
	entries []zeroAllocEntry

	// Index for fast lookup (hash -> entry index)
	// We use a fixed-size array to avoid map allocations
	index [CacheIndexSize]int32 // Power of 2 for fast modulo

	// Ring buffer for LRU eviction
	ring     []int32
	ringHead int32
	ringTail int32

	// Locks for each index bucket (striped locking)
	locks [CacheLockStripes]sync.RWMutex

	// Stats
	hits   uint64
	misses uint64
	stores uint64
}

// Fixed-size cache entry. Payload access (keyHash, wire,
// wireLen, expiry, occupied) is synchronised through mu:
// readers take RLock, writers take Lock. The earlier seqlock
// design still read the payload with ordinary loads while a
// writer held an odd seq, which is a data race under the Go
// memory model even if the retry logic discarded the snapshot.
type zeroAllocEntry struct {
	mu       sync.RWMutex
	keyHash  uint64                 // Hash of domain + qtype
	wire     [CacheMaxWireSize]byte // Wire format DNS message (CacheMaxWireSize bytes for EDNS0 support)
	wireLen  uint16                 // Actual length of wire data
	expiry   int64                  // Unix timestamp
	occupied int32                  // 0=empty, 1=occupied (guarded by mu)
}

const (
	maxEntries = CacheMaxEntries  // Total cache entries
	indexSize  = CacheIndexSize   // Must be power of 2
	lockStripe = CacheLockStripes // Number of lock stripes

	// Linear-probing sentinels. An index slot is either:
	//   indexEmpty     (-1): never used — probes stop here
	//   indexTombstone (-2): deleted — probes must keep going
	//   >= 0                : entry index
	// Tombstones are required because a plain -1 in the middle
	// of a probe cluster would hide later entries that hashed
	// to the same initial bucket.
	indexEmpty     int32 = -1
	indexTombstone int32 = -2
)

// NewZeroAllocCache creates a truly zero-allocation cache
// All memory is allocated upfront
func NewZeroAllocCache() *ZeroAllocCache {
	c := &ZeroAllocCache{
		entries: make([]zeroAllocEntry, maxEntries),
		ring:    make([]int32, maxEntries),
	}

	// Initialize index as empty
	for i := range c.index {
		c.index[i] = indexEmpty
	}

	// Initialize ring buffer
	for i := range c.ring {
		c.ring[i] = int32(i) //nolint:gosec // G115 - i is bounded by ring size
	}
	c.ringTail = int32(maxEntries - 1)

	// Start expiry checker
	go c.expiryLoop()

	return c
}

// GetEntry returns a copy of the cached wire format data.
//
// Walks the probe cluster directly: the stripe lock guards
// the index read, then the entry's own RWMutex guards payload
// validation and the wire copy. Lock ordering is strict —
// stripe lock is released before taking an entry lock, so the
// inverse path (entry lock then stripe lock in
// removeFromIndex) cannot deadlock.
func (c *ZeroAllocCache) GetEntry(qname string, qtype uint16) []byte {
	hash := hashKey(qname, qtype)
	bucket := hash & (indexSize - 1)

	for i := 0; i < CacheLinearProbeSize; i++ {
		testBucket := (bucket + uint64(i)) & (indexSize - 1) //nolint:gosec // G115 - i bounded
		lockIdx := testBucket & (lockStripe - 1)

		c.locks[lockIdx].RLock()
		idx := c.index[testBucket]
		c.locks[lockIdx].RUnlock()

		if idx == indexEmpty {
			break
		}
		if idx == indexTombstone {
			continue
		}

		entry := &c.entries[idx]
		entry.mu.RLock()
		if entry.occupied != 1 || entry.keyHash != hash {
			entry.mu.RUnlock()
			continue
		}

		now := time.Now().Unix()
		if now > entry.expiry {
			entry.mu.RUnlock()
			// Upgrade to exclusive and recheck: another
			// writer may have reused the slot in the gap.
			// Only remove the index slot if we were the ones
			// that actually marked this entry expired —
			// otherwise a concurrent refresh that replaced
			// this entry for the same hash would lose its
			// fresh index.
			entry.mu.Lock()
			cleared := false
			if entry.occupied == 1 && entry.keyHash == hash && time.Now().Unix() > entry.expiry {
				entry.occupied = 0
				cleared = true
			}
			entry.mu.Unlock()
			if cleared {
				c.removeFromIndex(hash, idx)
			}
			atomic.AddUint64(&c.misses, 1)
			return nil
		}

		out := make([]byte, entry.wireLen)
		copy(out, entry.wire[:entry.wireLen])
		entry.mu.RUnlock()

		atomic.AddUint64(&c.hits, 1)
		return out
	}

	atomic.AddUint64(&c.misses, 1)
	return nil
}

// allocateEntry gets the next entry using ring buffer (LRU)
func (c *ZeroAllocCache) allocateEntry() int32 {
	// Atomically increment and get the next position
	// Use CompareAndSwap loop to handle wraparound properly
	var head int32
	for {
		head = atomic.LoadInt32(&c.ringHead)
		next := (head + 1) % int32(maxEntries)
		if atomic.CompareAndSwapInt32(&c.ringHead, head, next) {
			break
		}
	}

	idx := c.ring[head]

	// Clear the old entry under its write lock so a concurrent
	// reader holding the RLock either sees the still-live
	// payload or waits until we've cleared occupied.
	oldEntry := &c.entries[idx]
	oldEntry.mu.Lock()
	stale := oldEntry.occupied == 1
	staleHash := oldEntry.keyHash
	if stale {
		oldEntry.occupied = 0
	}
	oldEntry.mu.Unlock()
	if stale {
		c.removeFromIndex(staleHash, idx)
	}

	return idx
}

// updateIndex updates the hash index.
//
// An update for an already-indexed hash must replace the
// existing slot, not append to the probe chain. The previous
// implementation inserted at the first empty slot, so a
// repeated store for the same key left the stale index ahead
// of the new one; once the stale entry's occupied flag flipped
// (expiry / ring eviction) findEntry hit a -1 bucket and
// stopped before reaching the fresh duplicate — hot keys
// effectively turned refresh-ineffective until unrelated ring
// pressure cleared them.
func (c *ZeroAllocCache) updateIndex(hash uint64, entryIdx int32) {
	bucket := hash & (indexSize - 1)

	// Walk the full probe cluster first to see if this hash is
	// already indexed — replacing in place avoids duplicate
	// slots for the same key. Also remember the first
	// empty-or-tombstoned slot; either is safe to reuse if no
	// existing slot is found.
	firstFree := int64(-1)
	for i := 0; i < CacheLinearProbeSize; i++ {
		testBucket := (bucket + uint64(i)) & (indexSize - 1) //nolint:gosec // G115 - i is bounded by probe size
		lockIdx := testBucket & (lockStripe - 1)

		c.locks[lockIdx].Lock()
		idx := c.index[testBucket]
		if idx == indexEmpty || idx == indexTombstone {
			if firstFree < 0 {
				firstFree = int64(testBucket)
			}
			c.locks[lockIdx].Unlock()
			// indexEmpty ends the cluster; no need to probe further
			// for an existing match because hash-equal entries
			// would have been placed before this empty slot.
			if idx == indexEmpty {
				break
			}
			continue
		}
		// keyHash is payload data guarded by entry.mu, not the
		// stripe lock held here. Compare under RLock so we
		// don't race a concurrent StoreWire that's mid-write
		// on the same entry.
		entry := &c.entries[idx]
		entry.mu.RLock()
		match := entry.keyHash == hash
		entry.mu.RUnlock()
		if match {
			c.index[testBucket] = entryIdx
			c.locks[lockIdx].Unlock()
			return
		}
		c.locks[lockIdx].Unlock()
	}

	if firstFree < 0 {
		return
	}
	lockIdx := uint64(firstFree) & (lockStripe - 1) //nolint:gosec // G115 - firstFree < indexSize
	c.locks[lockIdx].Lock()
	if cur := c.index[firstFree]; cur == indexEmpty || cur == indexTombstone {
		c.index[firstFree] = entryIdx
	}
	c.locks[lockIdx].Unlock()
}

// removeFromIndex clears the index slot that points at
// entryIdx. Matching on entry index (not just hash) is
// critical: after updateIndex replaces the slot for a hash
// with a newer entry, the displaced old entry still carries
// that keyHash. Later expiry/eviction of the old entry must
// not walk the probe chain, spot the fresh slot (same hash),
// and wipe it — removal targets the specific entry being
// cleaned up.
func (c *ZeroAllocCache) removeFromIndex(hash uint64, entryIdx int32) {
	bucket := hash & (indexSize - 1)

	for i := 0; i < CacheLinearProbeSize; i++ {
		testBucket := (bucket + uint64(i)) & (indexSize - 1) //nolint:gosec // G115 - i is bounded by probe size
		lockIdx := testBucket & (lockStripe - 1)

		c.locks[lockIdx].Lock()
		idx := c.index[testBucket]
		if idx == indexEmpty {
			// Walked off the cluster — target isn't indexed.
			c.locks[lockIdx].Unlock()
			return
		}
		if idx == entryIdx {
			// Tombstone, not empty: a later probe for a
			// colliding key must keep walking past this slot.
			c.index[testBucket] = indexTombstone
			c.locks[lockIdx].Unlock()
			return
		}
		c.locks[lockIdx].Unlock()
	}
}

// expiryLoop runs periodically to mark expired entries
func (c *ZeroAllocCache) expiryLoop() {
	ticker := time.NewTicker(CacheCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		for i := range c.entries {
			entry := &c.entries[i]
			entry.mu.Lock()
			expiredHash := uint64(0)
			expired := entry.occupied == 1 && now > entry.expiry
			if expired {
				expiredHash = entry.keyHash
				entry.occupied = 0
			}
			entry.mu.Unlock()
			if expired {
				c.removeFromIndex(expiredHash, int32(i)) //nolint:gosec // G115 - i < maxEntries, fits in int32
			}
		}
	}
}

// hashKey creates a hash from domain name and query type
// This is a very simple hash - in production you might want xxhash or similar
func hashKey(qname string, qtype uint16) uint64 {
	// FNV-1a hash
	hash := uint64(FNVOffsetBasis)

	// Hash qname bytes
	for i := 0; i < len(qname); i++ {
		hash ^= uint64(qname[i])
		hash *= FNVPrime
	}

	// Mix in qtype
	hash ^= uint64(qtype)
	hash *= FNVPrime

	return hash
}

// Get returns the cached DNS message (compatibility method for tests)
// This method DOES allocate as it needs to unpack the wire format
func (c *ZeroAllocCache) Get(qname string, qtype uint16, msgID ...uint16) any {
	wire := c.GetEntry(qname, qtype)
	if wire == nil {
		return nil
	}

	// If msgID provided, we're expected to return wire format with updated ID
	if len(msgID) > 0 {
		// Create a copy with updated message ID
		respWire := make([]byte, len(wire))
		copy(respWire, wire)
		UpdateMessageID(respWire, msgID[0])
		return respWire
	}

	// Otherwise unpack and return dns.Msg
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		zlog.Debug("Failed to unpack cached DNS message",
			zlog.String("query", qname),
			zlog.Int("qtype", int(qtype)),
			zlog.String("error", err.Error()))
		return nil
	}
	return msg
}

// Store stores both dns.Msg and wire format (compatibility wrapper)
func (c *ZeroAllocCache) Store(qname string, qtype uint16, data any, ttl ...uint32) {
	var wire []byte
	var ttlVal uint32 = CacheDefaultTTL // default

	switch v := data.(type) {
	case *dns.Msg:
		// Pack the message
		var err error
		wire, err = v.Pack()
		if err != nil {
			zlog.Debug("Failed to pack DNS message for cache storage",
				zlog.String("query", qname),
				zlog.Int("qtype", int(qtype)),
				zlog.String("error", err.Error()))
			return
		}
		// Get TTL from message if not provided
		if len(ttl) == 0 && len(v.Answer) > 0 {
			ttlVal = v.Answer[0].Header().Ttl
		}
	case []byte:
		// Already wire format
		wire = v
	default:
		zlog.Debug("Invalid data type for cache storage",
			zlog.String("query", qname),
			zlog.Int("qtype", int(qtype)),
			zlog.String("type", fmt.Sprintf("%T", data)))
		return
	}

	// Use provided TTL if given
	if len(ttl) > 0 {
		ttlVal = ttl[0]
	}

	c.StoreWire(qname, qtype, wire, ttlVal)
}

// StoreWire is the actual zero-alloc store method
func (c *ZeroAllocCache) StoreWire(qname string, qtype uint16, wire []byte, ttl uint32) {
	// Don't store if too large for our buffer
	if len(wire) > CacheMaxWireSize {
		zlog.Debug("Wire format too large for cache",
			zlog.String("query", qname),
			zlog.Int("qtype", int(qtype)),
			zlog.Int("size", len(wire)),
			zlog.Int("max_size", CacheMaxWireSize))
		return
	}

	// Don't cache 0 TTL
	if ttl == 0 {
		return
	}

	hash := hashKey(qname, qtype)

	// Get next entry from ring buffer
	idx := c.allocateEntry()
	entry := &c.entries[idx]

	// Publish under the entry's write lock. Readers holding
	// RLock on this entry will wait until we unlock; from
	// their perspective the entry transitions atomically from
	// "old state" to "fully-formed new state".
	entry.mu.Lock()
	entry.keyHash = hash
	copy(entry.wire[:], wire)                     // Copy into pre-allocated buffer
	entry.wireLen = uint16(len(wire))             //nolint:gosec // G115 - wire length is bounded by DNS message size
	entry.expiry = time.Now().Unix() + int64(ttl) //nolint:gosec // G115 - TTL is uint32, fits in int64
	entry.occupied = 1
	entry.mu.Unlock()

	// Update index after the entry is fully published.
	c.updateIndex(hash, idx)

	atomic.AddUint64(&c.stores, 1)
}

// Clear clears the cache (for tests)
func (c *ZeroAllocCache) Clear() {
	for i := range c.entries {
		c.entries[i].mu.Lock()
		c.entries[i].occupied = 0
		c.entries[i].mu.Unlock()
	}

	// Clear index
	for i := range c.index {
		c.index[i] = indexEmpty
	}

	// Reset stats
	atomic.StoreUint64(&c.hits, 0)
	atomic.StoreUint64(&c.misses, 0)
	atomic.StoreUint64(&c.stores, 0)
}

// Stats returns cache statistics
func (c *ZeroAllocCache) Stats() map[string]any {
	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	stores := atomic.LoadUint64(&c.stores)

	total := hits + misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hits) / float64(total) * PercentageMultiplier
	}

	// Count occupied entries
	occupied := 0
	for i := range c.entries {
		c.entries[i].mu.RLock()
		if c.entries[i].occupied == 1 {
			occupied++
		}
		c.entries[i].mu.RUnlock()
	}

	// GetEntry returns a heap copy of the wire bytes so the
	// caller can safely Unpack/WriteMsg without racing the
	// ring allocator. That means cache hits are no longer
	// strictly zero-allocation — report this honestly instead
	// of claiming zero_alloc=true and hiding a regression.
	return map[string]any{
		"hits":       hits,
		"misses":     misses,
		"stores":     stores,
		"hit_rate":   hitRate,
		"size":       occupied,
		"capacity":   maxEntries,
		"zero_alloc": false,
	}
}

// UpdateMessageID updates the message ID in wire format data
// This modifies the data in-place with zero allocations
func UpdateMessageID(wire []byte, msgID uint16) {
	if len(wire) >= WireMessageIDSize {
		binary.BigEndian.PutUint16(wire[WireMessageIDOffset:], msgID)
	} else {
		zlog.Debug("Wire format too small to update message ID",
			zlog.Int("size", len(wire)),
			zlog.Int("required", WireMessageIDSize))
	}
}

// GetMessageID extracts message ID from wire format
func GetMessageID(wire []byte) uint16 {
	if len(wire) >= WireMessageIDSize {
		return binary.BigEndian.Uint16(wire[WireMessageIDOffset:])
	}
	return 0
}
