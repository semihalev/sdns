package dnssec

import (
	"encoding/base64"

	"github.com/miekg/dns"
)

// keyTagChunk is how much of the encoded key is decoded at a time. It is a
// multiple of four so every chunk is whole base64 groups, and small enough
// that both buffers stay on the stack.
const keyTagChunk = 256

// KeyTag returns the RFC 4034 Appendix B key tag of a DNSKEY, agreeing with
// dns.DNSKEY.KeyTag on every input that one can answer for.
//
// The tag is a checksum over the record's RDATA, and the library computes it
// by packing that RDATA into a fixed buffer and summing it. The buffer itself
// stays on the stack; what does not is the key material, decoded in full so
// that it can be summed and dropped, one allocation the size of the key, per
// key, for a number sixteen bits wide.
//
// Nothing about the sum needs the octets to exist all at once, so this decodes
// a few hundred at a time into a stack buffer and accumulates as it goes.
//
// An encoding the chunked decode cannot read the same way a single decode
// would is handed to the library rather than guessed at, so the two agree on
// every input the library can answer for.
//
// RSAMD5 is derived here rather than delegated, because the library's
// derivation of it crashes; see rsamd5KeyTag.
func KeyTag(key *dns.DNSKEY) uint16 {
	if key == nil {
		return 0
	}
	if key.Algorithm == dns.RSAMD5 {
		return rsamd5KeyTag(key.PublicKey)
	}
	// The library packs the RDATA into a buffer to sum it, so a key too
	// large to pack has no tag. Judged on the encoded length, which is why
	// an oversized key costs nothing here rather than a decode.
	if oversizedKeyMaterial(key.PublicKey) {
		return 0
	}

	// RDATA is flags, protocol, algorithm, then the key: octets 0 and 2 are
	// at even offsets and shift, 1 and 3 are odd and do not.
	sum := uint32(key.Flags>>8)<<8 + uint32(key.Flags&0xFF) +
		uint32(key.Protocol)<<8 + uint32(key.Algorithm)

	// The key material begins at offset 4, so an octet's offset parity
	// within it is its parity in the RDATA.
	var (
		in      [keyTagChunk]byte
		out     [keyTagChunk / 4 * 3]byte
		encoded = key.PublicKey
	)
	for len(encoded) > 0 {
		n := min(len(encoded), keyTagChunk)
		copy(in[:n], encoded)
		encoded = encoded[n:]

		decoded, err := base64.StdEncoding.Decode(out[:], in[:n])
		if err != nil {
			// Not something a chunked read can judge, line breaks shift
			// the group boundaries, and a malformed key has to fail the
			// way the library fails it.
			return key.KeyTag()
		}
		// A short chunk before the end means padding appeared in the
		// middle, which a single decode would reject and this would not.
		if len(encoded) > 0 && decoded != len(out) {
			return key.KeyTag()
		}

		for i := range decoded {
			if i&1 == 0 {
				sum += uint32(out[i]) << 8
			} else {
				sum += uint32(out[i])
			}
		}
	}

	sum += sum >> 16 & 0xFFFF
	return uint16(sum & 0xFFFF)
}

// rsamd5KeyTag derives an RSAMD5 key's tag the way RFC 4034 Appendix B.1 and
// its errata 193 do: from the two octets below the last one of the modulus,
// rather than from the checksum every other algorithm uses.
//
// It is computed here rather than left to the library. The library used to
// derive it and read those three octets after checking only that the modulus
// had more than one, so material decoding to exactly two octets indexed below
// the start of a slice and panicked on a record that is attacker-supplied and
// whose tag is taken before anything about it has been validated. Since
// v1.1.73 the library does not derive it at all, a deprecated algorithm's
// special case, dropped, and answers with the checksum every other algorithm
// uses, so delegating now would return a tag Appendix B.1 does not define.
//
// Returning zero for every RSAMD5 key instead would be its own defect: zero is
// a tag a supported key can legitimately have, and the trust-anchor state
// keeps one anchor per tag, an RSAMD5 key mapped to zero could displace a
// real one. Only material too short to have a tag gets zero, which is what the
// library returns for it as well.
func rsamd5KeyTag(publicKey string) uint16 {
	var (
		in   [keyTagChunk]byte
		out  [keyTagChunk / 4 * 3]byte
		tail [3]byte
		seen int
	)
	for encoded := publicKey; len(encoded) > 0; {
		// Line breaks are dropped while filling rather than copied in: the
		// decoder skips them, so leaving them would let one land inside a
		// chunk and split a group that a single decode would have kept
		// whole. That is the difference between reading a wrapped key and
		// failing to.
		filled, consumed := fillKeyTagChunk(in[:], encoded)
		encoded = encoded[consumed:]

		// A decode error still yields the octets read before it, which is
		// the modulus the library would have gone on to use.
		decoded, err := base64.StdEncoding.Decode(out[:], in[:filled])
		for i := range decoded {
			tail[0], tail[1], tail[2] = tail[1], tail[2], out[i]
			if seen < len(tail) {
				seen++
			}
		}
		if err != nil {
			break
		}
		// A short chunk with material still to come means padding closed
		// the stream early, which is where a single decode stops too.
		if len(encoded) > 0 && decoded < len(out) {
			break
		}
	}
	if seen < len(tail) {
		return 0
	}
	return uint16(tail[0])<<8 | uint16(tail[1])
}

// fillKeyTagChunk copies base64 from encoded into dst, leaving out the CR and
// LF the decoder ignores, and reports how much of each it used.
func fillKeyTagChunk(dst []byte, encoded string) (filled, consumed int) {
	for consumed < len(encoded) && filled < len(dst) {
		c := encoded[consumed]
		consumed++
		if c == '\r' || c == '\n' {
			continue
		}
		dst[filled] = c
		filled++
	}
	return filled, consumed
}
