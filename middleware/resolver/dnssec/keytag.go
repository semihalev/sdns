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
// dns.DNSKEY.KeyTag on every input.
//
// The tag is a checksum over the record's RDATA, and the library computes it
// by packing that RDATA into a fixed buffer and summing it. The buffer itself
// stays on the stack; what does not is the key material, decoded in full so
// that it can be summed and dropped — one allocation the size of the key, per
// key, for a number sixteen bits wide.
//
// Nothing about the sum needs the octets to exist all at once, so this decodes
// a few hundred at a time into a stack buffer and accumulates as it goes.
//
// An encoding the chunked decode cannot read the same way a single decode
// would is handed to the library rather than guessed at, so the two agree on
// every input — with one deliberate exception.
//
// RSAMD5 has no tag here. It does not use this checksum at all: RFC 4034
// Appendix B.1 takes the tag from the modulus itself, and the library's
// implementation of that reads three octets after checking for two, so a
// DNSKEY whose material decodes to exactly two octets makes it index below
// the start of a slice and panic. That record is attacker-supplied and the
// tag is computed before anything has been validated. RFC 8624 §3.1 sets
// RSAMD5 to MUST NOT for validation and IsSupportedDNSKEYAlgorithm refuses
// it, so such a key can never validate anything; giving it no tag costs
// nothing and takes the crash off the path.
func KeyTag(key *dns.DNSKEY) uint16 {
	if key == nil {
		return 0
	}
	if key.Algorithm == dns.RSAMD5 {
		return 0
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
			// Not something a chunked read can judge — line breaks shift
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
