package dnssec

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/miekg/dns"
)

// maxDSKeyMaterial is how much decoded public key a DS digest may cover.
//
// The library packs the key into a 4096-octet buffer behind the four octets
// of flags, protocol and algorithm, so anything larger fails to pack and no
// DS is produced, a key that could never match. Computing the digest
// directly has no such ceiling of its own, and gaining one silently would
// widen what this resolver accepts as a chain of trust.
const maxDSKeyMaterial = 4096 - 4

// dsDigestHash maps a DS digest type to its hash, reporting whether this
// resolver will compute it at all.
//
// Digest type 5 is deliberately absent. miekg/dns names its constant SHA512,
// but IANA assigns 5 to GOST R 34.11-2012 (RFC 9558); the resolver's own
// IsSupportedDSDigest admits only 1, 2 and 4, and this must not disagree with
// it by treating a GOST digest as a SHA-512 one.
func dsDigestHash(digestType uint8) (crypto.Hash, bool) {
	switch digestType {
	case dns.SHA1:
		return crypto.SHA1, true
	case dns.SHA256:
		return crypto.SHA256, true
	case dns.SHA384:
		return crypto.SHA384, true
	default:
		return 0, false
	}
}

// oversizedKeyMaterial reports whether a DNSKEY carries more key material
// than maxDSKeyMaterial allows, judged on the encoded length so the answer
// is known before anything decodes it.
//
// An attacker-supplied DNSKEY can be as large as the message allows, and a
// DS set can name the same key many times over; deciding it is too big only
// after materializing it pays for the very thing being refused, once per
// mention.
func oversizedKeyMaterial(publicKey string) bool {
	limit := base64.StdEncoding.EncodedLen(maxDSKeyMaterial)
	if len(publicKey) <= limit {
		return false
	}
	// The decoder skips CR and LF, so a key that is only long because it
	// is wrapped is not oversized, and refusing it would reject an input
	// the library accepts. The line breaks are counted out rather than
	// assumed away, but only as far as the answer needs: once limit+1
	// octets of actual material have been seen, nothing in the rest can
	// bring the decoded length back under the limit. The walk is bounded
	// by the limit, not by the size of what an attacker sent.
	// Wrapping is the rare case, and the two searches below are the
	// assembly-optimized ones: limit+1 octets with no line break in them
	// settle it without a byte-at-a-time walk.
	head := publicKey[:limit+1]
	if strings.IndexByte(head, '\n') < 0 && strings.IndexByte(head, '\r') < 0 {
		return true
	}

	material := 0
	for i := range len(publicKey) {
		if c := publicKey[i]; c == '\r' || c == '\n' {
			continue
		}
		material++
		if material > limit {
			return true
		}
	}
	return false
}

// dsDigestMatches reports whether key hashes to want under digestType.
//
// This is the RFC 4034 §5.1.4 digest, hash(canonical owner name | flags |
// protocol | algorithm | public key), computed straight into the comparison.
// Producing a dns.DS to compare instead costs a 4096-octet key buffer, a
// 255-octet owner buffer, the record itself and a hexadecimal rendering of
// the digest, for every candidate key of every delegation; none of it is
// wanted here beyond the bytes.
func dsDigestMatches(key *dns.DNSKEY, digestType uint8, want []byte) bool {
	if key == nil || len(want) == 0 {
		return false
	}
	hash, ok := dsDigestHash(digestType)
	if !ok || !hash.Available() || hash.Size() != len(want) {
		return false
	}

	if oversizedKeyMaterial(key.PublicKey) {
		return false
	}

	// The public key travels as base64 in the record, so this decode is what
	// the digest is actually over.
	public, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(public) == 0 || len(public) > maxDSKeyMaterial {
		return false
	}

	name := dns.CanonicalName(key.Hdr.Name)
	owner := make([]byte, min(len(name)+1, 255))
	end, err := dns.PackDomainName(name, owner, 0, nil, false)
	if err != nil || end == 0 {
		return false
	}

	var rdata [4]byte
	binary.BigEndian.PutUint16(rdata[0:2], key.Flags)
	rdata[2] = key.Protocol
	rdata[3] = key.Algorithm

	digest := hash.New()
	digest.Write(owner[:end])
	digest.Write(rdata[:])
	digest.Write(public)

	// Sum into a stack buffer: the largest digest this accepts is SHA-512.
	var sum [64]byte
	return bytes.Equal(digest.Sum(sum[:0]), want)
}
