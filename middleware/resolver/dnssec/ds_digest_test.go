package dnssec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"runtime"
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
	// Type 5 is GOST R 34.11-2012 by IANA, not SHA-512, and this resolver
	// does not compute it; see dsDigestHash.
	digestTypes := []uint8{dns.SHA1, dns.SHA256, dns.SHA384}
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

	// Reserved, GOST-94, and a code no registry assigns: the library refuses
	// these too.
	for _, digestType := range []uint8{0, dns.GOST94, 200} {
		if key.ToDS(digestType) != nil {
			t.Fatalf("fixture is wrong: the library accepts digest type %d",
				digestType)
		}
		if dsDigestMatches(key, digestType, want) {
			t.Fatalf("accepted unsupported digest type %d", digestType)
		}
	}

	// Digest type 5 is the one deliberate divergence. miekg computes it as
	// SHA-512, following an expired draft; IANA assigns 5 to GOST R
	// 34.11-2012 (RFC 9558), and this resolver's IsSupportedDSDigest admits
	// only 1, 2 and 4. Treating a GOST digest as a SHA-512 one is the error
	// worth refusing, so this is stricter than the library on purpose.
	if key.ToDS(5) == nil {
		t.Fatal("fixture is wrong: the library no longer computes digest type 5")
	}
	if IsSupportedDSDigest(5) {
		t.Fatal("the resolver now admits digest type 5; this test and " +
			"dsDigestHash have to be revisited together")
	}
	library5, err := hex.DecodeString(key.ToDS(5).Digest)
	if err != nil {
		t.Fatalf("library digest is not hexadecimal: %v", err)
	}
	if dsDigestMatches(key, 5, library5) {
		t.Fatal("computed digest type 5 as SHA-512, which IANA assigns to GOST")
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

// TestDSDigestKeepsTheLibraryEnvelope pins the acceptance boundary. The
// library packs the key into a fixed buffer to build a DS, so a key larger
// than that buffer holds produces no DS and can never match. Computing the
// digest directly has no ceiling of its own, and gaining one silently would
// let a key the library refuses become a chain of trust.
func TestDSDigestKeepsTheLibraryEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		material int
	}{
		{"the largest key the library packs", maxDSKeyMaterial},
		{"one octet past it", maxDSKeyMaterial + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name: "example.com.", Rrtype: dns.TypeDNSKEY,
					Class: dns.ClassINET, Ttl: 3600,
				},
				Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256,
				PublicKey: base64.StdEncoding.EncodeToString(
					bytes.Repeat([]byte{0x5a}, tc.material)),
			}

			reference := key.ToDS(dns.SHA256)
			if tc.material > maxDSKeyMaterial {
				if reference != nil {
					t.Fatalf("fixture is wrong: the library packed %d octets "+
						"of key material", tc.material)
				}
				// Nothing the library would produce, so nothing may match:
				// the digest such a key would have if it were packable is
				// exactly what must be refused.
				digest := sha256.Sum256(oversizedDigestInput(t, key))
				if dsDigestMatches(key, dns.SHA256, digest[:]) {
					t.Fatal("accepted a key the library cannot turn into a DS")
				}
				return
			}

			if reference == nil {
				t.Fatalf("fixture is wrong: the library refused %d octets of "+
					"key material", tc.material)
			}
			want, err := hex.DecodeString(reference.Digest)
			if err != nil {
				t.Fatalf("library digest is not hexadecimal: %v", err)
			}
			if !dsDigestMatches(key, dns.SHA256, want) {
				t.Fatal("refused the largest key the library accepts")
			}
		})
	}
}

// oversizedMaterial is well past maxDSKeyMaterial, so a decode that should
// not happen is unmistakable in a measurement.
const oversizedMaterial = 48 << 10

func oversizedKey(algorithm uint8) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Flags: 257, Protocol: 3, Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{0x5a}, oversizedMaterial)),
	}
}

// TestDSDigestRefusesOversizedBeforeDecoding pins where the size limit is
// applied. A DNSKEY can be as large as the message allows and its material is
// attacker-supplied, so deciding it is too big has to happen on the encoded
// length — deciding it after decoding pays for the very thing being refused.
func TestDSDigestRefusesOversizedBeforeDecoding(t *testing.T) {
	key := oversizedKey(dns.RSASHA256)
	want := make([]byte, sha256.Size)

	allocs := testing.AllocsPerRun(100, func() {
		if dsDigestMatches(key, dns.SHA256, want) {
			t.Fatal("accepted an oversized key")
		}
	})
	if allocs != 0 {
		t.Fatalf("refusing a %d-octet key cost %.0f allocations; the length "+
			"check is running after the decode", oversizedMaterial, allocs)
	}
}

// TestDSDigestIgnoresWrappedKeyMaterial keeps the size check from narrowing
// what the library accepts.
//
// The limit is judged on the encoded length, but base64 decoding skips CR and
// LF — so a key at exactly the maximum, wrapped into lines, decodes to a
// packable key while measuring longer than the limit. Judging the raw length
// alone would refuse an input the library turns into a DS.
func TestDSDigestIgnoresWrappedKeyMaterial(t *testing.T) {
	material := bytes.Repeat([]byte{0x5a}, maxDSKeyMaterial)
	flat := base64.StdEncoding.EncodeToString(material)

	var wrapped strings.Builder
	for i := 0; i < len(flat); i += 64 {
		wrapped.WriteString(flat[i:min(i+64, len(flat))])
		wrapped.WriteString("\r\n")
	}
	if wrapped.Len() <= base64.StdEncoding.EncodedLen(maxDSKeyMaterial) {
		t.Fatal("fixture is wrong: the wrapped key is not longer than the limit")
	}

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256,
		PublicKey: wrapped.String(),
	}

	reference := key.ToDS(dns.SHA256)
	if reference == nil {
		t.Fatal("fixture is wrong: the library refused the wrapped key")
	}
	want, err := hex.DecodeString(reference.Digest)
	if err != nil {
		t.Fatalf("library digest is not hexadecimal: %v", err)
	}
	if !dsDigestMatches(key, dns.SHA256, want) {
		t.Fatal("refused a wrapped key the library accepts; the size check is " +
			"counting line breaks as key material")
	}
}

// TestVerifyDSRefusesOversizedKeyWithoutDecodingIt measures the path a query
// actually takes, which the helper-level test above does not.
//
// VerifyDS reaches usableDSCandidate before any digest, and that begins with
// KeyTag — which packs the key into a buffer of its own and decodes the
// material to fill it. Nothing about that decode depends on which DS is being
// considered, so a DS RRset naming the same key many times paid for it once
// per mention: one 48 KiB key across 32 DS records amplified to megabytes.
//
// The measurement is in bytes rather than allocations because the surrounding
// bookkeeping — deduplicating and sorting the DS records — allocates by
// design. The ceiling is one key's worth of material: crossing it means at
// least one decode happened, which is the thing being ruled out.
func TestVerifyDSRefusesOversizedKeyWithoutDecodingIt(t *testing.T) {
	const dsCount = 32
	key := oversizedKey(dns.RSASHA256)

	// The library cannot pack this key, so the tag it computes is 0 rather
	// than the key's real one. That is what an attacker indexes against.
	if tag := key.KeyTag(); tag != 0 {
		t.Fatalf("fixture is wrong: the library computed key tag %d for an "+
			"unpackable key", tag)
	}
	keyMap := map[uint16][]*dns.DNSKEY{0: {key}}

	// Distinct digests, so deduplication keeps all of them: every one is a
	// separate mention of the same key.
	dsSet := make([]dns.RR, 0, dsCount)
	for i := range dsCount {
		digest := bytes.Repeat([]byte{0x11}, sha256.Size)
		digest[0] = byte(i)
		dsSet = append(dsSet, &dns.DS{
			Hdr: dns.RR_Header{
				Name: "example.com.", Rrtype: dns.TypeDS,
				Class: dns.ClassINET, Ttl: 3600,
			},
			KeyTag: 0, Algorithm: dns.RSASHA256, DigestType: dns.SHA256,
			Digest: hex.EncodeToString(digest),
		})
	}

	if unsupportedOnly, err := VerifyDS(keyMap, dsSet); err == nil {
		t.Fatalf("an oversized key authenticated a DS (unsupportedOnly=%v)",
			unsupportedOnly)
	}

	const runs = 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		if _, err := VerifyDS(keyMap, dsSet); err == nil {
			t.Fatal("an oversized key authenticated a DS")
		}
	}
	runtime.ReadMemStats(&after)

	perCall := (after.TotalAlloc - before.TotalAlloc) / runs
	if perCall > oversizedMaterial {
		t.Fatalf("VerifyDS over %d DS records naming one %d-octet key "+
			"allocated %d B; the size check is running after KeyTag, so the "+
			"key is decoded once per DS", dsCount, oversizedMaterial, perCall)
	}
}

// oversizedDigestInput builds what the digest over key would be if the
// library could pack it, so the test compares against the one value that
// could plausibly be accepted rather than an arbitrary one.
func oversizedDigestInput(tb testing.TB, key *dns.DNSKEY) []byte {
	tb.Helper()
	name := dns.CanonicalName(key.Hdr.Name)
	owner := make([]byte, 255)
	end, err := dns.PackDomainName(name, owner, 0, nil, false)
	if err != nil {
		tb.Fatalf("PackDomainName: %v", err)
	}
	public, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		tb.Fatalf("key material is not base64: %v", err)
	}

	input := append([]byte(nil), owner[:end]...)
	var rdata [4]byte
	binary.BigEndian.PutUint16(rdata[0:2], key.Flags)
	rdata[2] = key.Protocol
	rdata[3] = key.Algorithm
	input = append(input, rdata[:]...)
	return append(input, public...)
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
