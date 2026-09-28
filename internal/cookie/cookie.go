// Package cookie classifies a query's DNS COOKIE option (RFC 7873) and
// builds the server's own: the interoperable version 1 server cookie of
// RFC 9018, a SipHash-2-4 MAC over the client cookie, the cookie's
// cleartext fields and the client address. Nothing is stored per client;
// a cookie is verified by computing it again.
package cookie

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
)

const (
	// ClientLen is the client cookie's length.
	ClientLen = 8
	// Len is a COOKIE option carrying a version 1 server cookie: the
	// client cookie and the 16-byte server cookie (RFC 9018 §4).
	Len = ClientLen + 16

	version = 1

	// A server cookie verifies from one hour in the past to five minutes
	// in the future, and one older than half an hour is replaced (RFC
	// 9018 §4.3).
	maxAge     = 3600
	maxSkew    = 300
	refreshAge = 1800
)

// Secret is the SipHash-2-4 key server cookies are made with.
type Secret struct{ k0, k1 uint64 }

// NewSecret derives the key from the configured secret. Thirty-two hex
// digits are the 128-bit key itself, so servers of one anycast set share
// cookies (RFC 9018 §4.4); any other text is hashed down to a key.
func NewSecret(s string) Secret {
	var key [16]byte
	if b, err := hex.DecodeString(s); err == nil && len(b) == len(key) {
		copy(key[:], b)
	} else {
		sum := sha256.Sum256([]byte(s))
		copy(key[:], sum[:])
	}
	return Secret{
		k0: binary.LittleEndian.Uint64(key[:8]),
		k1: binary.LittleEndian.Uint64(key[8:]),
	}
}

// Verdict is what a query's COOKIE option proves.
type Verdict uint8

const (
	// None: the query carries no COOKIE option.
	None Verdict = iota
	// ClientOnly: a client cookie alone.
	ClientOnly
	// Valid: a version 1 server cookie this server made for this client
	// cookie and address, within its lifetime.
	Valid
	// Invalid: a server cookie of a legal length that does not verify:
	// another shape, another version, expired, or forged.
	Invalid
	// Malformed: a length RFC 7873 §5.2.2 rejects, owed FORMERR.
	Malformed
)

// State is one query's classification, and what the reply's COOKIE option
// is built from.
type State struct {
	Verdict Verdict
	// echo marks a Valid server cookie young enough to return as it came.
	echo bool
	opt  [Len]byte
	addr netip.Addr
	now  uint32
}

// Classify judges opt, the query's first COOKIE option (nil when it has
// none), sent from addr at now, in seconds since the epoch.
func (s Secret) Classify(opt []byte, addr netip.Addr, now uint32) State {
	st := State{addr: addr.Unmap(), now: now}
	switch n := len(opt); {
	case opt == nil:
		st.Verdict = None
		return st
	case n == ClientLen:
		st.Verdict = ClientOnly
	case n < 16 || n > 40:
		st.Verdict = Malformed
		return st
	default:
		st.Verdict = Invalid
	}
	copy(st.opt[:ClientLen], opt)

	// Only a version 1 cookie of exactly this length is verified: the
	// fixed length is what keeps the MAC input unambiguous between the
	// address families (RFC 9018 §4.4).
	if len(opt) != Len || opt[ClientLen] != version || !st.addr.IsValid() {
		return st
	}
	// Serial number arithmetic (RFC 1982): the difference as a signed
	// 32-bit value orders the two across any wrap of the counter.
	age := int32(now - binary.BigEndian.Uint32(opt[12:16])) //nolint:gosec // the wrap is the arithmetic
	if age > maxAge || age < -maxSkew {
		return st
	}
	// The received Reserved bytes are hashed as they came, zero or not
	// (RFC 9018 §4.2).
	if s.mac(opt[:16], st.addr) != binary.LittleEndian.Uint64(opt[16:Len]) {
		return st
	}
	st.Verdict = Valid
	st.echo = age < refreshAge
	copy(st.opt[:], opt)
	return st
}

// Reply returns the COOKIE option to answer with: the client cookie and a
// server cookie, the query's own when it is Valid and young, otherwise a
// new one. ok is false when there is nothing to answer with, no client
// cookie or no address to bind one to.
func (s Secret) Reply(st *State) (opt [Len]byte, ok bool) {
	switch st.Verdict {
	case ClientOnly, Valid, Invalid:
	default:
		return opt, false
	}
	if st.echo {
		return st.opt, true
	}
	if !st.addr.IsValid() {
		return opt, false
	}
	copy(opt[:ClientLen], st.opt[:ClientLen])
	opt[ClientLen] = version // Reserved stays zero
	binary.BigEndian.PutUint32(opt[12:16], st.now)
	binary.LittleEndian.PutUint64(opt[16:], s.mac(opt[:16], st.addr))
	return opt, true
}

// mac is the Hash Sub-Field over the cookie's first 16 bytes, client
// cookie, Version, Reserved and Timestamp, then the address, 4 bytes for
// IPv4 and 16 for IPv6 (RFC 9018 §4.4).
func (s Secret) mac(head []byte, addr netip.Addr) uint64 {
	var in [32]byte
	n := copy(in[:], head[:16])
	if addr.Is4() {
		a := addr.As4()
		n += copy(in[n:], a[:])
	} else {
		a := addr.As16()
		n += copy(in[n:], a[:])
	}
	return sipHash24(s.k0, s.k1, in[:n])
}
