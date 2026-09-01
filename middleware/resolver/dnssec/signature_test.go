package dnssec

import (
	"crypto"
	"encoding/base64"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type signatureFixture struct {
	name  string
	key   *dns.DNSKEY
	sig   *dns.RRSIG
	rrset []dns.RR
}

// signatureFixtures signs one RRset per algorithm this package verifies.
func signatureFixtures(tb testing.TB) []signatureFixture {
	tb.Helper()
	inception := uint32(time.Now().Add(-time.Hour).Unix())      //nolint:gosec // test epoch fits
	expiration := uint32(time.Now().Add(24 * time.Hour).Unix()) //nolint:gosec // test epoch fits

	var fixtures []signatureFixture
	for _, spec := range []struct {
		name      string
		algorithm uint8
		bits      int
	}{
		{"RSASHA1", dns.RSASHA1, 1024},
		{"RSASHA256", dns.RSASHA256, 1024},
		{"RSASHA512", dns.RSASHA512, 1024},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, 256},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384, 384},
		{"ED25519", dns.ED25519, 256},
	} {
		key := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name: "example.com.", Rrtype: dns.TypeDNSKEY,
				Class: dns.ClassINET, Ttl: 3600,
			},
			Flags: 257, Protocol: 3, Algorithm: spec.algorithm,
		}
		private, err := key.Generate(spec.bits)
		if err != nil {
			tb.Fatalf("%s: generate: %v", spec.name, err)
		}

		rrset := []dns.RR{
			mustSignatureRR(tb, "www.example.com. 300 IN A 192.0.2.10"),
			mustSignatureRR(tb, "www.example.com. 300 IN A 192.0.2.11"),
		}
		sig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name: "www.example.com.", Rrtype: dns.TypeRRSIG,
				Class: dns.ClassINET, Ttl: 300,
			},
			TypeCovered: dns.TypeA, Algorithm: spec.algorithm, Labels: 3,
			OrigTtl: 300, Expiration: expiration, Inception: inception,
			KeyTag: key.KeyTag(), SignerName: key.Hdr.Name,
		}
		signer, ok := private.(crypto.Signer)
		if !ok {
			tb.Fatalf("%s: generated key does not sign", spec.name)
		}
		if err := sig.Sign(signer, rrset); err != nil {
			tb.Fatalf("%s: sign: %v", spec.name, err)
		}
		fixtures = append(fixtures, signatureFixture{
			name: spec.name, key: key, sig: sig, rrset: rrset,
		})
	}
	return fixtures
}

func mustSignatureRR(tb testing.TB, s string) dns.RR {
	tb.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		tb.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

// TestVerifySignatureRefusesLooseECDSALength documents the one place this
// package is deliberately stricter than the library.
//
// RFC 6605 §4 fixes r and s at the curve's width. The library splits whatever
// it is handed in half and lets a zero-padded 66-octet P-256 signature
// through; that is not a P-256 signature, and no signer emits one. Refusing
// it narrows what this resolver accepts, which is the safe direction, but it
// is a divergence, so it is written down rather than left to be discovered.
func TestVerifySignatureRefusesLooseECDSALength(t *testing.T) {
	var fixture signatureFixture
	for _, candidate := range signatureFixtures(t) {
		if candidate.name == "ECDSAP256SHA256" {
			fixture = candidate
			break
		}
	}
	if fixture.key == nil {
		t.Fatal("no ECDSA fixture")
	}

	raw, err := base64.StdEncoding.DecodeString(fixture.sig.Signature)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	// One leading zero octet on each of r and s: the same integers, a width
	// the RFC does not give them.
	half := len(raw) / 2
	padded := make([]byte, 0, len(raw)+2)
	padded = append(padded, 0)
	padded = append(padded, raw[:half]...)
	padded = append(padded, 0)
	padded = append(padded, raw[half:]...)

	loose := *fixture.sig
	loose.Signature = base64.StdEncoding.EncodeToString(padded)

	if err := loose.Verify(fixture.key, fixture.rrset); err != nil {
		t.Skipf("the library no longer accepts a padded ECDSA signature (%v); "+
			"this divergence has closed on its own", err)
	}
	if err := verifySignature(fixture.key, &loose, fixture.rrset); err == nil {
		t.Fatal("accepted an ECDSA signature whose r and s are not the " +
			"curve's width")
	}
}

// TestSignatureBindingRequiresALabelBoundary pins the second place this
// package is stricter than the library.
//
// RFC 4035 §5.3.1 requires the signer name to be the zone containing the
// RRset. The library tests that with a plain string suffix, its own comment
// concedes that is the best it can do without SOA context, which reads
// evilexample.com. as inside example.com. The resolver enforces real zone
// containment a layer up, so nothing reaches this on that path, but a
// primitive whose check only means something because of its caller is one
// refactor away from meaning nothing.
func TestSignatureBindingRequiresALabelBoundary(t *testing.T) {
	fixture := signatureFixtures(t)[0]

	// Same string suffix as the signer, different zone.
	impostor := []dns.RR{
		mustSignatureRR(t, "www.evilexample.com. 300 IN A 192.0.2.10"),
	}
	sig := *fixture.sig
	sig.Hdr.Name = "www.evilexample.com."

	if err := signatureBinding(fixture.key, &sig, impostor); err == nil {
		t.Fatal("bound a signature signed by example.com. to an RRset in " +
			"evilexample.com.")
	}

	// The apex itself, and a name genuinely below it, must still bind.
	for _, owner := range []string{"example.com.", "deep.www.example.com."} {
		rrset := []dns.RR{
			mustSignatureRR(t, owner+" 300 IN A 192.0.2.10"),
		}
		inZone := *fixture.sig
		inZone.Hdr.Name = owner
		inZone.Labels = uint8(dns.CountLabel(owner)) //nolint:gosec // test names are short
		if err := signatureBinding(fixture.key, &inZone, rrset); err != nil {
			t.Fatalf("refused %s, which is in the signer's zone: %v", owner, err)
		}
	}
}

// Test_VerifyRRSIG_EscapedDotIsNotALabelBoundary is the production-path
// regression for the same defect one level up.
//
// `foo\.zone.example.` is a single label `foo.zone` under `example.`, it
// ends with the *text* of the signer zone while living outside it. Signed
// with the zone's own valid key, a containment check written as a string
// suffix authenticates it: a zone operator would be able to sign answers for
// owners no delegation ever gave them.
func Test_VerifyRRSIG_EscapedDotIsNotALabelBoundary(t *testing.T) {
	signerZone := "zone.example."
	key, priv := makeZoneKey(t, signerZone)
	keys := map[uint16][]*dns.DNSKEY{key.KeyTag(): {key}}

	impostor := &dns.A{
		Hdr: dns.RR_Header{
			Name: `foo\.zone.example.`, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 300,
		},
		A: []byte{192, 0, 2, 66},
	}
	sig := signRRSet(t, key, priv, []dns.RR{impostor})

	msg := new(dns.Msg)
	msg.SetQuestion(`foo\.zone.example.`, dns.TypeA)
	msg.Answer = []dns.RR{impostor, sig}

	if ok, err := VerifyRRSIG(signerZone, keys, msg); ok && err == nil {
		t.Fatal("BUG REPRODUCED: an RRset whose owner is a single label " +
			`containing a literal dot (foo\.zone.example.) authenticated ` +
			"against the zone.example. key; the escaped dot was read as a " +
			"label separator")
	}

	// The genuine descendant, spelled with a real separator, still validates:
	// the fix must not cost the ordinary name.
	genuine := &dns.A{
		Hdr: dns.RR_Header{
			Name: "foo.zone.example.", Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 300,
		},
		A: []byte{192, 0, 2, 67},
	}
	genuineSig := signRRSet(t, key, priv, []dns.RR{genuine})

	valid := new(dns.Msg)
	valid.SetQuestion("foo.zone.example.", dns.TypeA)
	valid.Answer = []dns.RR{genuine, genuineSig}

	ok, err := VerifyRRSIG(signerZone, keys, valid)
	if err != nil {
		t.Fatalf("a genuine in-zone RRset failed to validate: %v", err)
	}
	if !ok {
		t.Fatal("a genuine in-zone RRset did not validate")
	}
}

// TestVerifySignatureAgreesWithLibrary is the contract that lets this package
// verify signatures itself: for the signatures a signer produces, and for
// inputs corrupted in the ways a resolver actually meets, it must reach the
// same verdict as dns.RRSIG.Verify. The two documented divergences, a
// malformed ECDSA length, and crypto/rsa's modulus minimum under a GODEBUG,
// are covered separately; everything here must agree.
func TestVerifySignatureAgreesWithLibrary(t *testing.T) {
	for _, fixture := range signatureFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			assert := func(what string, key *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) {
				t.Helper()
				libraryOK := sig.Verify(key, rrset) == nil
				ourOK := verifySignature(key, sig, rrset) == nil
				if libraryOK != ourOK {
					t.Fatalf("%s: library accepts=%v, we accept=%v",
						what, libraryOK, ourOK)
				}
			}

			assert("the signature as signed", fixture.key, fixture.sig, fixture.rrset)

			// A signature altered in one octet.
			tampered := *fixture.sig
			raw, err := base64.StdEncoding.DecodeString(fixture.sig.Signature)
			if err != nil {
				t.Fatalf("signature is not base64: %v", err)
			}
			raw[len(raw)-1] ^= 0x01
			tampered.Signature = base64.StdEncoding.EncodeToString(raw)
			assert("an altered signature", fixture.key, &tampered, fixture.rrset)

			// A record altered after signing.
			altered := []dns.RR{dns.Copy(fixture.rrset[0]), fixture.rrset[1]}
			altered[0].(*dns.A).A[3]++
			assert("an altered RRset", fixture.key, fixture.sig, altered)

			// A record removed from the set.
			assert("a truncated RRset", fixture.key, fixture.sig, fixture.rrset[:1])

			// Another key of the same algorithm.
			other := &dns.DNSKEY{
				Hdr:   fixture.key.Hdr,
				Flags: 257, Protocol: 3, Algorithm: fixture.key.Algorithm,
			}
			if _, err := other.Generate(len(fixture.key.PublicKey) * 3); err == nil {
				other.Hdr.Name = fixture.key.Hdr.Name
				assert("another key", other, fixture.sig, fixture.rrset)
			}

			// Bindings the preflight is responsible for.
			for _, tc := range []struct {
				what   string
				mutate func(*dns.DNSKEY, *dns.RRSIG)
			}{
				{"a key tag that does not match", func(_ *dns.DNSKEY, s *dns.RRSIG) {
					s.KeyTag++
				}},
				{"a signer that is not the key's owner", func(_ *dns.DNSKEY, s *dns.RRSIG) {
					s.SignerName = "other.example."
				}},
				{"a covered type that is not the RRset's", func(_ *dns.DNSKEY, s *dns.RRSIG) {
					s.TypeCovered = dns.TypeAAAA
				}},
				{"a label count above the owner's", func(_ *dns.DNSKEY, s *dns.RRSIG) {
					s.Labels = 9
				}},
				{"a key that is not a zone key", func(k *dns.DNSKEY, _ *dns.RRSIG) {
					k.Flags &^= dns.ZONE
				}},
				{"a protocol that is not 3", func(k *dns.DNSKEY, _ *dns.RRSIG) {
					k.Protocol = 2
				}},
			} {
				key := *fixture.key
				sig := *fixture.sig
				tc.mutate(&key, &sig)
				assert(tc.what, &key, &sig, fixture.rrset)
			}
		})
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	for _, fixture := range signatureFixtures(b) {
		b.Run(fixture.name+"/owned", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := verifySignature(fixture.key, fixture.sig, fixture.rrset); err != nil {
					b.Fatalf("verify: %v", err)
				}
			}
		})
		b.Run(fixture.name+"/library", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := fixture.sig.Verify(fixture.key, fixture.rrset); err != nil {
					b.Fatalf("verify: %v", err)
				}
			}
		})
	}
}
