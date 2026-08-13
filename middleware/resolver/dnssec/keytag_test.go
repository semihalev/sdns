package dnssec

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestKeyTagMatchesLibrary is the contract: for every key a resolver meets,
// the tag must be the one dns.DNSKEY.KeyTag computes. A tag that differs by
// one does not fail loudly — it silently stops a DS or an RRSIG from finding
// the key that would have validated it.
func TestKeyTagMatchesLibrary(t *testing.T) {
	for _, key := range dsDigestTestKeys(t) {
		if got, want := KeyTag(key), key.KeyTag(); got != want {
			t.Fatalf("%s alg %d: tag %d, library says %d",
				key.Hdr.Name, key.Algorithm, got, want)
		}
	}

	// Flags and protocol are in the sum, so varying them varies the tag.
	base := dsDigestTestKeys(t)[0]
	for _, flags := range []uint16{0, 1, 256, 257, 385, 0xFFFF} {
		for _, protocol := range []uint8{0, 3, 255} {
			key := *base
			key.Flags = flags
			key.Protocol = protocol
			if got, want := KeyTag(&key), key.KeyTag(); got != want {
				t.Fatalf("flags %d protocol %d: tag %d, library says %d",
					flags, protocol, got, want)
			}
		}
	}
}

// TestKeyTagMatchesLibraryAcrossChunkBoundaries walks the key material past
// the size the fast path decodes at a time. The sum is position-weighted, so
// a chunk boundary that lost or shifted a byte's parity would produce a
// plausible tag that is not the right one.
func TestKeyTagMatchesLibraryAcrossChunkBoundaries(t *testing.T) {
	// Every decoded length either side of a chunk, and several chunks deep.
	const decodedPerChunk = keyTagChunk / 4 * 3
	var sizes []int
	for _, chunks := range []int{0, 1, 2, 7} {
		for _, delta := range []int{-3, -2, -1, 0, 1, 2, 3} {
			if size := chunks*decodedPerChunk + delta; size > 0 {
				sizes = append(sizes, size)
			}
		}
	}
	sizes = append(sizes, 1, 2, 3, maxDSKeyMaterial)

	for _, size := range sizes {
		material := make([]byte, size)
		for i := range material {
			material[i] = byte(i*7 + 1)
		}
		key := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name: "example.com.", Rrtype: dns.TypeDNSKEY,
				Class: dns.ClassINET, Ttl: 3600,
			},
			Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256,
			PublicKey: base64.StdEncoding.EncodeToString(material),
		}
		if got, want := KeyTag(key), key.KeyTag(); got != want {
			t.Fatalf("%d octets of key material: tag %d, library says %d",
				size, got, want)
		}
	}
}

// TestKeyTagMatchesLibraryOnMalformedKeys pins the inputs the fast path hands
// back. Whatever the library makes of them, this must make the same.
func TestKeyTagMatchesLibraryOnMalformedKeys(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 300))
	wrapped := valid[:64] + "\r\n" + valid[64:]

	for _, tc := range []struct {
		name      string
		publicKey string
	}{
		{"empty", ""},
		{"not base64", "not base64!!"},
		{"a length that is not whole groups", valid[:len(valid)-1]},
		{"padding in the middle", valid[:64] + "=" + valid[65:]},
		{"line breaks the decoder skips", wrapped},
		{"one octet", base64.StdEncoding.EncodeToString([]byte{0x01})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name: "example.com.", Rrtype: dns.TypeDNSKEY,
					Class: dns.ClassINET, Ttl: 3600,
				},
				Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256,
				PublicKey: tc.publicKey,
			}
			if got, want := KeyTag(key), key.KeyTag(); got != want {
				t.Fatalf("tag %d, library says %d", got, want)
			}
		})
	}
}

// TestKeyTagRefusesOversizedWithoutDecoding pins the reason this exists at
// all for the DS path: a key too large to pack has no tag, and finding that
// out must not cost the decode the tag would have needed.
func TestKeyTagRefusesOversizedWithoutDecoding(t *testing.T) {
	key := oversizedKey(dns.RSASHA256)
	if tag := key.KeyTag(); tag != 0 {
		t.Fatalf("fixture is wrong: the library computed tag %d for an "+
			"unpackable key", tag)
	}

	allocs := testing.AllocsPerRun(100, func() {
		if tag := KeyTag(key); tag != 0 {
			t.Fatalf("tag %d for an unpackable key", tag)
		}
	})
	if allocs != 0 {
		t.Fatalf("refusing an oversized key cost %.0f allocations", allocs)
	}
}

// TestKeyTagDoesNotAllocate is the point: a DNSKEY set is read for every
// validated delegation, and every key in it is tagged.
func TestKeyTagDoesNotAllocate(t *testing.T) {
	for _, key := range dsDigestTestKeys(t) {
		allocs := testing.AllocsPerRun(200, func() {
			if KeyTag(key) == 0 {
				t.Fatal("no tag")
			}
		})
		if allocs != 0 {
			t.Fatalf("%s alg %d cost %.0f allocations",
				key.Hdr.Name, key.Algorithm, allocs)
		}
	}
}

// TestKeyTagGivesRSAMD5NoTag records the one deliberate divergence, and the
// crash behind it.
//
// RFC 4034 Appendix B.1 derives the RSAMD5 tag from the modulus rather than
// from the checksum. The library implements that by reading three octets from
// the end of the decoded modulus after checking that it has more than one, so
// a DNSKEY whose material decodes to exactly two octets indexes below the
// start of a slice. The record is attacker-supplied and the tag is computed
// before anything about it has been validated.
//
// RFC 8624 §3.1 makes RSAMD5 MUST NOT for validation and
// IsSupportedDNSKEYAlgorithm refuses it, so a key that carries it can never
// validate anything and losing its tag costs nothing.
func TestKeyTagGivesRSAMD5NoTag(t *testing.T) {
	if IsSupportedDNSKEYAlgorithm(dns.RSAMD5) {
		t.Fatal("the resolver now validates RSAMD5; this divergence and " +
			"KeyTag have to be revisited together")
	}

	rsamd5 := func(publicKey string) *dns.DNSKEY {
		return &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name: "example.com.", Rrtype: dns.TypeDNSKEY,
				Class: dns.ClassINET, Ttl: 3600,
			},
			Flags: 257, Protocol: 3, Algorithm: dns.RSAMD5,
			PublicKey: publicKey,
		}
	}

	// The shape that crashes the library: two decoded octets.
	crasher := rsamd5(base64.StdEncoding.EncodeToString([]byte{0x30, 0x30}))
	func() {
		defer func() {
			if recover() == nil {
				t.Log("the library no longer panics on a two-octet RSAMD5 " +
					"modulus; the divergence may be reconsidered")
			}
		}()
		_ = crasher.KeyTag()
	}()
	if got := KeyTag(crasher); got != 0 {
		t.Fatalf("tag %d for an RSAMD5 key, want 0", got)
	}

	// And an ordinary one, which the library handles but we still refuse.
	ordinary := rsamd5(base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x5a}, 130)))
	if got := KeyTag(ordinary); got != 0 {
		t.Fatalf("tag %d for an RSAMD5 key, want 0", got)
	}
}

// TestKeyTagSurvivesAdversarialKeys is the property behind the RSAMD5
// divergence, stated for every algorithm rather than the one that happened to
// crash: a DNSKEY arrives from the network and its tag is computed before
// anything about it has been validated, so no key material may do worse than
// produce a wrong-looking number.
func TestKeyTagSurvivesAdversarialKeys(t *testing.T) {
	algorithms := []uint8{
		dns.RSAMD5, dns.DSA, dns.RSASHA1, dns.RSASHA1NSEC3SHA1,
		dns.RSASHA256, dns.RSASHA512, dns.ECCGOST, dns.ECDSAP256SHA256,
		dns.ECDSAP384SHA384, dns.ED25519, dns.ED448, 0, 99, 255,
	}
	materials := []string{
		"", "=", "==", "===", "A", "AA", "AA==", "AAA=", "AAAA",
		// One and two decoded octets: the lengths the library's RSAMD5
		// branch admits and then reads three from.
		base64.StdEncoding.EncodeToString([]byte{0x01}),
		base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}),
		base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}),
		"\x00", "\r\n", "AAAA\r\n", strings.Repeat("A", 4096),
		strings.Repeat("=", 8), "not base64 at all",
	}

	for _, algorithm := range algorithms {
		for _, material := range materials {
			for _, flags := range []uint16{0, 256, 257, 0xFFFF} {
				key := &dns.DNSKEY{
					Hdr: dns.RR_Header{
						Name: "example.com.", Rrtype: dns.TypeDNSKEY,
						Class: dns.ClassINET, Ttl: 3600,
					},
					Flags: flags, Protocol: 3, Algorithm: algorithm,
					PublicKey: material,
				}
				// A panic here fails the test by escaping it; naming the
				// input is what makes the failure usable.
				func() {
					defer func() {
						if p := recover(); p != nil {
							t.Fatalf("alg %d flags %d key %q: %v",
								algorithm, flags, material, p)
						}
					}()
					_ = KeyTag(key)
				}()
			}
		}
	}
}

func BenchmarkKeyTag(b *testing.B) {
	for _, key := range dsDigestTestKeys(b) {
		name := strings.ToLower(dns.AlgorithmToString[key.Algorithm])
		b.Run(name+"/owned", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if KeyTag(key) == 0 {
					b.Fatal("no tag")
				}
			}
		})
		b.Run(name+"/library", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if key.KeyTag() == 0 {
					b.Fatal("no tag")
				}
			}
		})
	}
}
