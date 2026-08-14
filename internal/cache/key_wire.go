package cache

import (
	"net/netip"

	"github.com/cespare/xxhash/v2"
)

// This file computes the cache key directly from an uncompressed wire-form
// question name, producing bit-identical hashes to Key/KeyString/
// KeyWithPrefix over the presentation-format name miekg's UnpackDomainName
// would decode from the same bytes. That equivalence is the canonical-key
// contract: entries written through the Msg path resolve through the wire
// path and vice versa, with no cache flush across the boundary.
//
// The preimage is unchanged:
//
//	[qclass:2 BE][qtype:2 BE][cd:1][folded presentation qname]
//	(+ ECS: [family 4|6][prefix bits][address bytes, bit-rounded])
//
// where "folded presentation qname" is the presentation form with ASCII
// A–Z lowered. Escapes mirror UnpackDomainName exactly: the special set
// {'.', ' ', '\”, '@', ';', '(', ')', '"', '\\'} is backslash-prefixed,
// bytes outside 0x20–0x7E become \DDD (three decimal digits), everything
// else passes literally. Escape digits and specials are never A–Z, so
// folding the escaped form equals escaping the folded form.

// maxWireNameOctets is the RFC 1035 name length bound in wire form.
const maxWireNameOctets = 255

// wireKeyHasher streams preimage bytes into an xxhash digest through a
// stack chunk, so key computation touches no heap regardless of caller.
type wireKeyHasher struct {
	digest xxhash.Digest
	chunk  [192]byte
	n      int
}

func (h *wireKeyHasher) init() { h.digest.Reset() }

func (h *wireKeyHasher) writeByte(b byte) {
	if h.n == len(h.chunk) {
		h.flush()
	}
	h.chunk[h.n] = b
	h.n++
}

func (h *wireKeyHasher) flush() {
	if h.n > 0 {
		_, _ = h.digest.Write(h.chunk[:h.n])
		h.n = 0
	}
}

func (h *wireKeyHasher) sum() uint64 {
	h.flush()
	return h.digest.Sum64()
}

func (h *wireKeyHasher) writeHeader(qtype, qclass uint16, cd bool) {
	h.writeByte(byte(qclass >> 8))
	h.writeByte(byte(qclass & 0xFF))
	h.writeByte(byte(qtype >> 8))
	h.writeByte(byte(qtype & 0xFF))
	if cd {
		h.writeByte(1)
	} else {
		h.writeByte(0)
	}
}

// isPresentationSpecial mirrors miekg's isDomainNameLabelSpecial.
func isPresentationSpecial(b byte) bool {
	switch b {
	case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
		return true
	}
	return false
}

// writeWireName streams the folded presentation form of an uncompressed
// wire name. wireName must be exactly the name region: labels terminated by
// the root byte, nothing after. Compression pointers, reserved label types,
// truncation, oversized names, or trailing bytes refuse (the strict path's
// eligibility promises none of these; refusal here is the backstop).
func (h *wireKeyHasher) writeWireName(wireName []byte) bool {
	if len(wireName) == 0 || len(wireName) > maxWireNameOctets {
		return false
	}
	off := 0
	wroteLabel := false
	for {
		if off >= len(wireName) {
			return false
		}
		c := int(wireName[off])
		off++
		if c == 0 {
			break
		}
		if c&0xC0 != 0 {
			return false
		}
		if off+c > len(wireName) {
			return false
		}
		for _, b := range wireName[off : off+c] {
			switch {
			case isPresentationSpecial(b):
				h.writeByte('\\')
				h.writeByte(b)
			case b < ' ' || b > '~':
				h.writeByte('\\')
				h.writeByte('0' + b/100)
				h.writeByte('0' + b/10%10)
				h.writeByte('0' + b%10)
			default:
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				h.writeByte(b)
			}
		}
		h.writeByte('.')
		off += c
		wroteLabel = true
	}
	if off != len(wireName) {
		return false
	}
	if !wroteLabel {
		// The root name decodes to ".".
		h.writeByte('.')
	}
	return true
}

// KeyWire computes Key/KeyString's hash from an uncompressed wire-form
// question name. ok is false when the name is not a plain, exactly-consumed
// uncompressed name — the caller falls back to the decoded path.
func KeyWire(wireName []byte, qtype, qclass uint16, cd bool) (hash uint64, ok bool) {
	var h wireKeyHasher
	h.init()
	h.writeHeader(qtype, qclass, cd)
	if !h.writeWireName(wireName) {
		return 0, false
	}
	return h.sum(), true
}

// KeyWireWithPrefix is KeyWire with KeyWithPrefix's ECS extension. An
// invalid prefix collapses to KeyWire, exactly as KeyWithPrefix collapses
// to Key.
func KeyWireWithPrefix(
	wireName []byte,
	qtype, qclass uint16,
	cd bool,
	prefix netip.Prefix,
) (hash uint64, ok bool) {
	if !prefix.IsValid() {
		return KeyWire(wireName, qtype, qclass, cd)
	}

	var h wireKeyHasher
	h.init()
	h.writeHeader(qtype, qclass, cd)
	if !h.writeWireName(wireName) {
		return 0, false
	}

	bits := prefix.Bits()
	var addr16 [16]byte
	var addrBytes []byte
	if prefix.Addr().Is4() {
		a4 := prefix.Addr().As4()
		copy(addr16[:], a4[:])
		addrBytes = addr16[:4]
		h.writeByte(4)
	} else {
		addr16 = prefix.Addr().As16()
		addrBytes = addr16[:]
		h.writeByte(6)
	}
	addrLen := min((bits+7)/8, len(addrBytes))
	h.writeByte(byte(bits)) //nolint:gosec // 0 ≤ bits ≤ 128
	for _, b := range addrBytes[:addrLen] {
		h.writeByte(b)
	}
	return h.sum(), true
}
