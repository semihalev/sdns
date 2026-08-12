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

// TestVerifySignatureAgreesWithLibrary is the contract that lets this package
// verify signatures itself: for every input, valid or not, it must reach the
// same verdict as dns.RRSIG.Verify. Anything else is either a signature the
// library would have rejected being accepted here, or the reverse.
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
