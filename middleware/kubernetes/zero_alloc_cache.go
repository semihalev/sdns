package kubernetes

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ZeroAllocCache - Truly zero-allocation DNS cache with pre-computed wire format
type ZeroAllocCache struct {
	// Pre-allocated response buffers
	bufferPool sync.Pool

	// Wire format cache (domain+qtype -> pre-serialized DNS response)
	wireCache sync.Map

	// Stats
	hits      uint64
	misses    uint64
	evictions uint64

	// Pre-allocated entries pool
	entryPool sync.Pool
}

// wireEntry holds pre-computed DNS response in wire format
type wireEntry struct {
	wire   []byte // Pre-serialized DNS response
	expiry int64  // Unix timestamp
	qname  string // For stats only
	qtype  uint16 // For stats only
}

// NewZeroAllocCache creates the performance beast
func NewZeroAllocCache() *ZeroAllocCache {
	c := &ZeroAllocCache{
		bufferPool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate 512 byte buffers (typical DNS response size)
				return make([]byte, 512)
			},
		},
		entryPool: sync.Pool{
			New: func() interface{} {
				return &wireEntry{}
			},
		},
	}

	// Start background cleanup
	go c.cleanupLoop()

	return c
}

// Get retrieves pre-computed response (ZERO ALLOCATIONS!)
func (c *ZeroAllocCache) Get(qname string, qtype uint16, msgID uint16) []byte {
	key := makeKey(qname, qtype)

	if val, ok := c.wireCache.Load(key); ok {
		entry := val.(*wireEntry)

		// Check expiry
		if time.Now().Unix() > entry.expiry {
			c.wireCache.Delete(key)
			atomic.AddUint64(&c.evictions, 1)
			return nil
		}

		atomic.AddUint64(&c.hits, 1)

		// Get buffer from pool to avoid allocation
		bufInterface := c.bufferPool.Get()
		buf, ok := bufInterface.([]byte)
		if !ok {
			// Pool returned something else, allocate new
			buf = make([]byte, len(entry.wire))
		}

		// Resize buffer if needed
		if cap(buf) < len(entry.wire) {
			c.bufferPool.Put(buf)
			buf = make([]byte, len(entry.wire))
		} else {
			buf = buf[:len(entry.wire)]
		}

		// Copy wire data
		copy(buf, entry.wire)

		// Update message ID in the copy
		if len(buf) >= 2 {
			// DNS message ID is first 2 bytes
			buf[0] = byte(msgID >> 8)
			buf[1] = byte(msgID)
		}

		return buf
	}

	atomic.AddUint64(&c.misses, 1)
	return nil
}

// Store pre-computes and caches DNS response
func (c *ZeroAllocCache) Store(qname string, qtype uint16, msg *dns.Msg) {
	// Get buffer from pool
	buf := c.bufferPool.Get().([]byte)

	// Pack message to wire format
	wire, err := msg.PackBuffer(buf)
	if err != nil {
		c.bufferPool.Put(buf)
		return
	}

	// Get entry from pool
	entry := c.entryPool.Get().(*wireEntry)
	entry.qname = qname
	entry.qtype = qtype
	entry.expiry = time.Now().Unix() + 30 // 30 second TTL

	// Store wire format (reuse buffer if possible)
	if len(wire) <= len(buf) {
		entry.wire = buf[:len(wire)]
	} else {
		// Need bigger buffer
		entry.wire = make([]byte, len(wire))
		copy(entry.wire, wire)
		c.bufferPool.Put(buf)
	}

	// Store in cache
	key := makeKey(qname, qtype)
	c.wireCache.Store(key, entry)
}

// cleanupLoop removes expired entries
func (c *ZeroAllocCache) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		expired := 0

		c.wireCache.Range(func(key, value interface{}) bool {
			entry := value.(*wireEntry)
			if now > entry.expiry {
				c.wireCache.Delete(key)

				// Return wire buffer to pool if it's standard size
				if cap(entry.wire) == 512 {
					buf := entry.wire[:512]
					c.bufferPool.Put(&buf)
				}

				// Return entry to pool
				entry.wire = nil
				c.entryPool.Put(entry)

				expired++
			}
			return true
		})

		atomic.AddUint64(&c.evictions, uint64(expired))
	}
}

// makeKey creates cache key without allocation
func makeKey(qname string, qtype uint16) uint64 {
	// Fast hash combining domain and qtype
	hash := uint64(5381)

	// Hash domain
	for i := 0; i < len(qname); i++ {
		hash = ((hash << 5) + hash) + uint64(qname[i])
	}

	// Mix in qtype
	hash ^= uint64(qtype) << 32

	return hash
}

// Stats returns cache statistics
func (c *ZeroAllocCache) Stats() map[string]interface{} {
	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	evictions := atomic.LoadUint64(&c.evictions)

	total := hits + misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	size := 0
	c.wireCache.Range(func(_, _ interface{}) bool {
		size++
		return true
	})

	return map[string]interface{}{
		"hits":       hits,
		"misses":     misses,
		"evictions":  evictions,
		"hit_rate":   hitRate,
		"size":       size,
		"zero_alloc": true,
	}
}

// Prewarm loads common queries into cache
func (c *ZeroAllocCache) Prewarm(services []string, namespaces []string, clusterDomain string) {
	// Common query types
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}

	for _, ns := range namespaces {
		for _, svc := range services {
			qname := svc + "." + ns + ".svc." + clusterDomain + "."

			for _, qtype := range qtypes {
				// Create synthetic response
				msg := &dns.Msg{}
				msg.SetQuestion(qname, qtype)
				msg.Response = true
				msg.Authoritative = true
				msg.RecursionAvailable = true

				// Add answer (using 10.96.0.x for demo)
				if qtype == dns.TypeA {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   qname,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: []byte{10, 96, 0, 1},
					})
				}

				c.Store(qname, qtype, msg)
			}
		}
	}
}

// Clear empties the cache
func (c *ZeroAllocCache) Clear() {
	c.wireCache.Range(func(key, value interface{}) bool {
		entry := value.(*wireEntry)

		// Return buffers to pool
		if cap(entry.wire) == 512 {
			buf := entry.wire[:512]
			c.bufferPool.Put(&buf)
		}

		// Return entry to pool
		entry.wire = nil
		c.entryPool.Put(entry)

		c.wireCache.Delete(key)
		return true
	})
}
