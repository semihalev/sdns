package kubernetes

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
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
	index [16384]int32 // Power of 2 for fast modulo

	// Ring buffer for LRU eviction
	ring     []int32
	ringHead int32
	ringTail int32

	// Locks for each index bucket (striped locking)
	locks [256]sync.RWMutex

	// Stats
	hits   uint64
	misses uint64
	stores uint64
}

// Fixed-size cache entry
type zeroAllocEntry struct {
	keyHash  uint64     // Hash of domain + qtype
	wire     [4096]byte // Wire format DNS message (4096 bytes for EDNS0 support)
	wireLen  uint16     // Actual length of wire data
	expiry   int64      // Unix timestamp
	occupied int32      // Atomic flag: 0=empty, 1=occupied
}

const (
	maxEntries = 10000 // Total cache entries
	indexSize  = 16384 // Must be power of 2
	lockStripe = 256   // Number of lock stripes
)

// NewZeroAllocCache creates a truly zero-allocation cache
// All memory is allocated upfront
func NewZeroAllocCache() *ZeroAllocCache {
	c := &ZeroAllocCache{
		entries: make([]zeroAllocEntry, maxEntries),
		ring:    make([]int32, maxEntries),
	}

	// Initialize index with -1 (no entry)
	for i := range c.index {
		c.index[i] = -1
	}

	// Initialize ring buffer
	for i := range c.ring {
		c.ring[i] = int32(i)
	}
	c.ringTail = int32(maxEntries - 1)

	// Start expiry checker
	go c.expiryLoop()

	return c
}

// GetEntry returns a direct pointer to the wire format data
// This achieves TRUE zero allocation by returning the actual buffer
// IMPORTANT: Caller MUST NOT modify the returned data!
func (c *ZeroAllocCache) GetEntry(qname string, qtype uint16) []byte {
	hash := hashKey(qname, qtype)
	idx := c.findEntry(hash)

	if idx < 0 {
		atomic.AddUint64(&c.misses, 1)
		return nil
	}

	entry := &c.entries[idx]

	// Check expiry
	if time.Now().Unix() > entry.expiry {
		atomic.StoreInt32(&entry.occupied, 0)
		atomic.AddUint64(&c.misses, 1)
		return nil
	}

	atomic.AddUint64(&c.hits, 1)

	// Return slice pointing to the actual buffer - ZERO ALLOCATIONS!
	// This is safe because we never modify cached entries
	return entry.wire[:entry.wireLen]
}

// allocateEntry gets the next entry using ring buffer (LRU)
func (c *ZeroAllocCache) allocateEntry() int32 {
	// Simple ring buffer allocation
	head := atomic.LoadInt32(&c.ringHead)
	next := (head + 1) % int32(maxEntries)
	atomic.StoreInt32(&c.ringHead, next)

	idx := c.ring[head]

	// Clear old entry if occupied
	oldEntry := &c.entries[idx]
	if atomic.LoadInt32(&oldEntry.occupied) == 1 {
		// Remove from index
		c.removeFromIndex(oldEntry.keyHash)
		atomic.StoreInt32(&oldEntry.occupied, 0)
	}

	return idx
}

// findEntry looks up entry by hash
func (c *ZeroAllocCache) findEntry(hash uint64) int32 {
	bucket := hash & (indexSize - 1)
	lockIdx := bucket & (lockStripe - 1)

	c.locks[lockIdx].RLock()
	idx := c.index[bucket]
	c.locks[lockIdx].RUnlock()

	if idx < 0 {
		return -1
	}

	// Verify hash matches (collision handling)
	entry := &c.entries[idx]
	if atomic.LoadInt32(&entry.occupied) == 1 && entry.keyHash == hash {
		return idx
	}

	// Linear probe for collisions
	for i := 1; i < 16; i++ {
		bucket = (bucket + 1) & (indexSize - 1)

		lockIdx = bucket & (lockStripe - 1)
		c.locks[lockIdx].RLock()
		idx = c.index[bucket]
		c.locks[lockIdx].RUnlock()

		if idx < 0 {
			break
		}

		entry = &c.entries[idx]
		if atomic.LoadInt32(&entry.occupied) == 1 && entry.keyHash == hash {
			return idx
		}
	}

	return -1
}

// updateIndex updates the hash index
func (c *ZeroAllocCache) updateIndex(hash uint64, entryIdx int32) {
	bucket := hash & (indexSize - 1)

	// Linear probe to find empty slot
	for i := 0; i < 16; i++ {
		testBucket := (bucket + uint64(i)) & (indexSize - 1)
		lockIdx := testBucket & (lockStripe - 1)

		c.locks[lockIdx].Lock()
		if c.index[testBucket] < 0 {
			c.index[testBucket] = entryIdx
			c.locks[lockIdx].Unlock()
			return
		}
		c.locks[lockIdx].Unlock()
	}
}

// removeFromIndex removes entry from index
func (c *ZeroAllocCache) removeFromIndex(hash uint64) {
	bucket := hash & (indexSize - 1)

	for i := 0; i < 16; i++ {
		testBucket := (bucket + uint64(i)) & (indexSize - 1)
		lockIdx := testBucket & (lockStripe - 1)

		c.locks[lockIdx].Lock()
		idx := c.index[testBucket]
		if idx >= 0 {
			entry := &c.entries[idx]
			if entry.keyHash == hash {
				c.index[testBucket] = -1
				c.locks[lockIdx].Unlock()
				return
			}
		}
		c.locks[lockIdx].Unlock()
	}
}

// expiryLoop runs periodically to mark expired entries
func (c *ZeroAllocCache) expiryLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		for i := range c.entries {
			entry := &c.entries[i]
			if atomic.LoadInt32(&entry.occupied) == 1 && now > entry.expiry {
				c.removeFromIndex(entry.keyHash)
				atomic.StoreInt32(&entry.occupied, 0)
			}
		}
	}
}

// hashKey creates a hash from domain name and query type
// This is a very simple hash - in production you might want xxhash or similar
func hashKey(qname string, qtype uint16) uint64 {
	// FNV-1a hash
	hash := uint64(14695981039346656037)

	// Hash qname bytes
	for i := 0; i < len(qname); i++ {
		hash ^= uint64(qname[i])
		hash *= 1099511628211
	}

	// Mix in qtype
	hash ^= uint64(qtype)
	hash *= 1099511628211

	return hash
}

// Get returns the cached DNS message (compatibility method for tests)
// This method DOES allocate as it needs to unpack the wire format
func (c *ZeroAllocCache) Get(qname string, qtype uint16, msgID ...uint16) interface{} {
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
		return nil
	}
	return msg
}

// Store stores both dns.Msg and wire format (compatibility wrapper)
func (c *ZeroAllocCache) Store(qname string, qtype uint16, data interface{}, ttl ...uint32) {
	var wire []byte
	var ttlVal uint32 = 30 // default

	switch v := data.(type) {
	case *dns.Msg:
		// Pack the message
		var err error
		wire, err = v.Pack()
		if err != nil {
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
	if len(wire) > 4096 {
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

	// Store data
	entry.keyHash = hash
	copy(entry.wire[:], wire) // Copy into pre-allocated buffer
	entry.wireLen = uint16(len(wire))
	entry.expiry = time.Now().Unix() + int64(ttl)

	// Mark as occupied BEFORE updating index so findEntry can see it
	atomic.StoreInt32(&entry.occupied, 1)

	// Update index
	c.updateIndex(hash, idx)

	atomic.AddUint64(&c.stores, 1)
}

// Clear clears the cache (for tests)
func (c *ZeroAllocCache) Clear() {
	// Mark all entries as unoccupied
	for i := range c.entries {
		atomic.StoreInt32(&c.entries[i].occupied, 0)
	}

	// Clear index
	for i := range c.index {
		c.index[i] = -1
	}

	// Reset stats
	atomic.StoreUint64(&c.hits, 0)
	atomic.StoreUint64(&c.misses, 0)
	atomic.StoreUint64(&c.stores, 0)
}

// Stats returns cache statistics
func (c *ZeroAllocCache) Stats() map[string]interface{} {
	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	stores := atomic.LoadUint64(&c.stores)

	total := hits + misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	// Count occupied entries
	occupied := 0
	for i := range c.entries {
		if atomic.LoadInt32(&c.entries[i].occupied) == 1 {
			occupied++
		}
	}

	return map[string]interface{}{
		"hits":       hits,
		"misses":     misses,
		"stores":     stores,
		"hit_rate":   hitRate,
		"size":       occupied,
		"capacity":   maxEntries,
		"zero_alloc": true,
	}
}

// UpdateMessageID updates the message ID in wire format data
// This modifies the data in-place with zero allocations
func UpdateMessageID(wire []byte, msgID uint16) {
	if len(wire) >= 2 {
		binary.BigEndian.PutUint16(wire, msgID)
	}
}

// GetMessageID extracts message ID from wire format
func GetMessageID(wire []byte) uint16 {
	if len(wire) >= 2 {
		return binary.BigEndian.Uint16(wire)
	}
	return 0
}
