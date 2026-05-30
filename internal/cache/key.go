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
	buf = append(buf, byte(q.Qclass>>8), byte(q.Qclass&0xFF)) //nolint:gosec // intentional uint16 byte extraction

	// Add query type (2 bytes, big-endian)
	buf = append(buf, byte(q.Qtype>>8), byte(q.Qtype&0xFF)) //nolint:gosec // intentional uint16 byte extraction

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
	buf = append(buf, byte(qclass>>8), byte(qclass&0xFF)) //nolint:gosec // intentional uint16 byte extraction

	// Add query type (2 bytes, big-endian)
	buf = append(buf, byte(qtype>>8), byte(qtype&0xFF)) //nolint:gosec // intentional uint16 byte extraction

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

// KeyWithScope is an ECS-aware variant of Key. When scope is the
// empty slice (the canonical "no scope" value) the returned hash is
// bit-identical to Key(q, cd), so cache entries written before this
// function existed still resolve on lookup — no flush needed on
// upgrade.
//
// When scope is non-empty the bytes are folded into the hash
// preimage with a single-byte length prefix so a /24 keyed entry
// can't collide with a /20 of the same address. Callers should pass
// scope as `prefix.Addr().AsSlice()[:prefixLenBytes]` rounded up
// to the nearest byte; the helper does no normalisation.
func KeyWithScope(q dns.Question, cd bool, scope []byte) uint64 {
	if len(scope) == 0 {
		return Key(q, cd)
	}

	kb := keyBufferPool.Get().(*keyBuffer)
	buf := kb.buf[:0]

	// Same prefix as Key so a scoped key with len(scope)==0 (handled
	// above) and an unscoped Key collide deliberately.
	buf = append(buf, byte(q.Qclass>>8), byte(q.Qclass&0xFF)) //nolint:gosec // intentional uint16 byte extraction
	buf = append(buf, byte(q.Qtype>>8), byte(q.Qtype&0xFF))   //nolint:gosec // intentional uint16 byte extraction

	if cd {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	nameLen := len(q.Name)
	if len(buf)+nameLen+1+len(scope) > len(kb.buf) {
		// Extremely long qnames or future scope widening could push
		// past the on-stack buffer; fall through to heap. Rare.
		newBuf := make([]byte, len(buf), len(buf)+nameLen+1+len(scope))
		copy(newBuf, buf)
		buf = newBuf
	}

	for i := range nameLen {
		c := q.Name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf = append(buf, c)
	}

	// Scope length first so a /24 prefix can't be confused with a
	// /20 truncation of the same address. Callers (CacheKey.Hash)
	// always supply at most 16 bytes (full IPv6 address), so this
	// truncating cast can't lose information in practice.
	scopeLen := min(len(scope), 255)
	buf = append(buf, byte(scopeLen)) //nolint:gosec // bounded above
	buf = append(buf, scope[:scopeLen]...)

	hash := xxhash.Sum64(buf)
	keyBufferPool.Put(kb)
	return hash
}

// KeySimple generates a cache key without pooling for comparison.
// This is exported for benchmarking purposes only.
func KeySimple(q dns.Question, cd ...bool) uint64 {
	bufSize := 2 + 2 + 1 + len(q.Name)
	buf := make([]byte, 0, bufSize)

	buf = append(buf, byte(q.Qclass>>8), byte(q.Qclass&0xFF)) //nolint:gosec // intentional uint16 byte extraction
	buf = append(buf, byte(q.Qtype>>8), byte(q.Qtype&0xFF))   //nolint:gosec // intentional uint16 byte extraction

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
