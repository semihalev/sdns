// Package cache provides DNS caching functionality for SDNS.
package cache

import (
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
)

// keyBuffer holds a reusable buffer for key generation.
type keyBuffer struct {
	buf [256]byte // Stack-allocated array to avoid heap allocations
}

// Pool for key buffers.
var keyBufferPool = sync.Pool{
	New: func() any {
		return new(keyBuffer)
	},
}

// Key generates a cache key for DNS queries.
// This implementation uses object pooling and stack allocation to achieve zero heap allocations.
// The optional cd parameter indicates if the CD (Checking Disabled) bit should be included.
func Key(q dns.Question, cd ...bool) uint64 {
	// Get buffer from pool
	kb := keyBufferPool.Get().(*keyBuffer)
	buf := kb.buf[:0]

	// Build key components
	// Format: [qclass:2][qtype:2][dnssec:1][qname:variable]

	// Add query class (2 bytes, big-endian)
	buf = append(buf, byte(q.Qclass>>8), byte(q.Qclass))

	// Add query type (2 bytes, big-endian)
	buf = append(buf, byte(q.Qtype>>8), byte(q.Qtype))

	// Add CD flag if specified
	if len(cd) > 0 && cd[0] {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Add normalized domain name (lowercase)
	nameLen := len(q.Name)
	if len(buf)+nameLen > len(kb.buf) {
		// For extremely long domain names, fall back to heap allocation
		// This should be very rare in practice
		newBuf := make([]byte, len(buf), len(buf)+nameLen)
		copy(newBuf, buf)
		buf = newBuf
	}

	// Normalize domain name
	for i := 0; i < nameLen; i++ {
		c := q.Name[i]
		// Convert uppercase ASCII to lowercase
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf = append(buf, c)
	}

	// Calculate hash
	hash := xxhash.Sum64(buf)

	// Return buffer to pool
	keyBufferPool.Put(kb)

	return hash
}

// KeyString is an optimized version for string-based keys.
// It uses unsafe conversion to avoid allocation when converting string to []byte.
func KeyString(qname string, qtype, qclass uint16, cd bool) uint64 {
	// Get buffer from pool
	kb := keyBufferPool.Get().(*keyBuffer)
	buf := kb.buf[:0]

	// Add query class (2 bytes, big-endian)
	buf = append(buf, byte(qclass>>8), byte(qclass))

	// Add query type (2 bytes, big-endian)
	buf = append(buf, byte(qtype>>8), byte(qtype))

	// Add CD flag
	if cd {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Add normalized domain name
	nameLen := len(qname)
	if len(buf)+nameLen > len(kb.buf) {
		// Fall back to heap allocation for extremely long names
		newBuf := make([]byte, len(buf), len(buf)+nameLen)
		copy(newBuf, buf)
		buf = newBuf
	}

	// Normalize domain name directly from string
	for i := 0; i < nameLen; i++ {
		c := qname[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf = append(buf, c)
	}

	// Calculate hash
	hash := xxhash.Sum64(buf)

	// Return buffer to pool
	keyBufferPool.Put(kb)

	return hash
}

// KeySimple generates a cache key without pooling for comparison.
// This is exported for benchmarking purposes only.
func KeySimple(q dns.Question, cd ...bool) uint64 {
	bufSize := 2 + 2 + 1 + len(q.Name)
	buf := make([]byte, 0, bufSize)

	buf = append(buf, byte(q.Qclass>>8), byte(q.Qclass))
	buf = append(buf, byte(q.Qtype>>8), byte(q.Qtype))

	if len(cd) > 0 && cd[0] {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	for i := 0; i < len(q.Name); i++ {
		c := q.Name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf = append(buf, c)
	}

	return xxhash.Sum64(buf)
}
