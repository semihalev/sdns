package dnssec

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// dsDigestTestKeys returns keys spanning the algorithms and key sizes a
// resolver meets, including a revoked and a zone-signing key: the digest is
// over the flags, so those are distinct inputs rather than cosmetic ones.
func dsDigestTestKeys(tb testing.TB) []*dns.DNSKEY {
	tb.Helper()
	var keys []*dns.DNSKEY
	for _, spec := range []struct {
		owner     string
		flags     uint16
		algorithm uint8
		bits      int
	}{
		{"example.com.", 257, dns.RSASHA256, 1024},
		{"example.com.", 256, dns.RSASHA256, 1024},
		{"example.com.", 257, dns.RSASHA512, 1024},
		{"EXAMPLE.com.", 257, dns.RSASHA256, 1024},
		{"a.deeper.example.com.", 257, dns.ECDSAP256SHA256, 256},
		{"example.com.", 257, dns.ECDSAP384SHA384, 384},
		{"example.com.", 257, dns.ED25519, 256},
		{".", 257, dns.ECDSAP256SHA256, 256},
		{"xn--nme-qla.example.", 257, dns.ECDSAP256SHA256, 256},
	} {
		key := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name: spec.owner, Rrtype: dns.TypeDNSKEY,
				Class: dns.ClassINET, Ttl: 3600,
			},
			Flags: spec.flags, Protocol: 3, Algorithm: spec.algorithm,
		}
		if _, err := key.Generate(spec.bits); err != nil {
			tb.Fatalf("generate %s/%d: %v", spec.owner, spec.algorithm, err)
		}
		keys = append(keys, key)
	}
	return keys
}

// TestDSDigestMatchesLibrary is the contract that lets the digest be compared
// without building a DS record: for every key, algorithm and digest type, it
// must accept exactly the digest dns.DNSKEY.ToDS produces and nothing else.
func TestDSDigestMatchesLibrary(t *testing.T) {
	digestTypes := []uint8{dns.SHA1, dns.SHA256, dns.SHA384, dns.SHA512}
	keys := dsDigestTestKeys(t)

	for _, key := range keys {
		for _, digestType := range digestTypes {
			reference := key.ToDS(digestType)
			if reference == nil {
				t.Fatalf("%s alg %d digest %d: library produced no DS",
					key.Hdr.Name, key.Algorithm, digestType)
			}
			want, err := hex.DecodeString(reference.Digest)
			if err != nil {
				t.Fatalf("library digest is not hexadecimal: %v", err)
			}

			if !dsDigestMatches(key, digestType, want) {
				t.Fatalf("%s alg %d digest %d: rejected the library's own digest",
					key.Hdr.Name, key.Algorithm, digestType)
			}

			// A digest that differs anywhere must be refused.
			flipped := append([]byte(nil), want...)
			flipped[len(flipped)-1] ^= 0x01
			if dsDigestMatches(key, digestType, flipped) {
				t.Fatalf("%s alg %d digest %d: accepted an altered digest",
					key.Hdr.Name, key.Algorithm, digestType)
			}
			if dsDigestMatches(key, digestType, want[:len(want)-1]) {
				t.Fatal("accepted a truncated digest")
			}

			// Another key's digest must not match this one.
			for _, other := range keys {
				if other == key {
					continue
				}
				otherDS := other.ToDS(digestType)
				otherDigest, err := hex.DecodeString(otherDS.Digest)
				if err != nil {
					t.Fatalf("library digest is not hexadecimal: %v", err)
				}
				if dsDigestMatches(key, digestType, otherDigest) {
					t.Fatalf("%s accepted the digest of %s",
						key.Hdr.Name, other.Hdr.Name)
				}
			}
		}
	}
}

// TestDSDigestRejectsWhatTheLibraryRejects pins the refusals: an unsupported
// digest type, and key material that is not decodable.
func TestDSDigestRejectsWhatTheLibraryRejects(t *testing.T) {
	key := dsDigestTestKeys(t)[0]
	reference := key.ToDS(dns.SHA256)
	want, err := hex.DecodeString(reference.Digest)
	if err != nil {
		t.Fatalf("library digest is not hexadecimal: %v", err)
	}

	// Reserved, GOST (which the library declines to compute), and a code no
	// registry assigns. SHA-512 is 5 and is supported, so it is not here.
	for _, digestType := range []uint8{0, dns.GOST94, 200} {
		if key.ToDS(digestType) != nil {
			t.Fatalf("fixture is wrong: the library accepts digest type %d",
				digestType)
		}
		if dsDigestMatches(key, digestType, want) {
			t.Fatalf("accepted unsupported digest type %d", digestType)
		}
	}

	broken := *key
	broken.PublicKey = "not base64!!"
	if dsDigestMatches(&broken, dns.SHA256, want) {
		t.Fatal("accepted a key whose material does not decode")
	}

	if dsDigestMatches(nil, dns.SHA256, want) {
		t.Fatal("accepted a missing key")
	}
	if dsDigestMatches(key, dns.SHA256, nil) {
		t.Fatal("accepted a missing digest")
	}
}

// TestDSDigestNameFolding pins that the owner name is canonicalized the way
// the library canonicalizes it: the digest is over the lowercased name, so a
// parent publishing either spelling must match.
func TestDSDigestNameFolding(t *testing.T) {
	key := dsDigestTestKeys(t)[0]
	reference := key.ToDS(dns.SHA256)
	want, err := hex.DecodeString(reference.Digest)
	if err != nil {
		t.Fatalf("library digest is not hexadecimal: %v", err)
	}

	shouted := *key
	shouted.Hdr.Name = strings.ToUpper(key.Hdr.Name)
	if !dsDigestMatches(&shouted, dns.SHA256, want) {
		t.Fatal("the owner name was not folded before hashing")
	}
}

func BenchmarkDSDigestMatches(b *testing.B) {
	key := dsDigestTestKeys(b)[0]
	want, err := hex.DecodeString(key.ToDS(dns.SHA256).Digest)
	if err != nil {
		b.Fatalf("library digest is not hexadecimal: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if !dsDigestMatches(key, dns.SHA256, want) {
			b.Fatal("digest did not match")
		}
	}
}

func BenchmarkDSDigestViaToDS(b *testing.B) {
	key := dsDigestTestKeys(b)[0]
	want := key.ToDS(dns.SHA256).Digest

	b.ReportAllocs()
	for b.Loop() {
		ds := key.ToDS(dns.SHA256)
		if ds == nil || !strings.EqualFold(ds.Digest, want) {
			b.Fatal("digest did not match")
		}
	}
}
