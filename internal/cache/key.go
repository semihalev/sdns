// Package cache provides DNS caching functionality for SDNS.
package cache

import (
	"net/netip"
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

// KeyWithPrefix is an ECS-aware variant of Key. An invalid prefix
// (the canonical "no scope" value) collapses to Key(q, cd) so cache
// entries written before this function existed still resolve on
// lookup — no flush needed on upgrade.
//
// When prefix is valid, family + bit-length + the address bytes
// rounded up to a byte are folded into the hash preimage. The
// distinct family byte means an IPv4 /24 of [a, b, c] cannot
// collide with an IPv6 /24 whose first three bytes happen to be
// [a, b, c]. The distinct bit-length byte means /22 and /24 of
// 203.0.112.0 hash differently even though their byte-rounded
// addresses are both [203, 0, 112] — the earlier scope-bytes-only
// encoding aliased here and would serve a wider supernet's answer
// to a narrower-subnet query.
func KeyWithPrefix(q dns.Question, cd bool, prefix netip.Prefix) uint64 {
	if !prefix.IsValid() {
		return Key(q, cd)
	}

	bits := prefix.Bits()
	addrBytes := prefix.Addr().AsSlice()
	addrLen := min((bits+7)/8, len(addrBytes))

	kb := keyBufferPool.Get().(*keyBuffer)
	buf := kb.buf[:0]

	// Same prefix as Key so a KeyWithPrefix call with an invalid
	// prefix (handled above) and an unscoped Key collide deliberately.
	buf = append(buf, byte(q.Qclass>>8), byte(q.Qclass&0xFF)) //nolint:gosec // intentional uint16 byte extraction
	buf = append(buf, byte(q.Qtype>>8), byte(q.Qtype&0xFF))   //nolint:gosec // intentional uint16 byte extraction

	if cd {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	nameLen := len(q.Name)
	// Reserve space for qname + family byte + bits byte + scope bytes.
	required := len(buf) + nameLen + 2 + addrLen
	if required > len(kb.buf) {
		newBuf := make([]byte, len(buf), required)
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

	// Family: 4 for IPv4, 6 for IPv6 (mirrors the human-meaningful
	// shorthand, not the wire-format Family field which uses 1/2).
	// Distinct values prevent a v4 scope from colliding with a v6
	// scope whose first bytes happen to match.
	if prefix.Addr().Is4() {
		buf = append(buf, 4)
	} else {
		buf = append(buf, 6)
	}
	// Bit-length so /22 and /24 of the same byte-rounded address
	// hash differently. Bits is at most 128, fits a single byte.
	buf = append(buf, byte(bits)) //nolint:gosec // 0 ≤ bits ≤ 128
	buf = append(buf, addrBytes[:addrLen]...)

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
