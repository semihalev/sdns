package dnssec

import (
	"crypto/mldsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mldsaFixture signs an RRset with ML-DSA-44 the way
// draft-westerbaan-dnssec-mldsa describes: the bare FIPS 204 key and
// signature, pure ML-DSA over the RFC 4034 signed data, with the context
// given. The dns library cannot sign algorithm 18, so the signature is
// computed here over this package's own signed-data construction.
func mldsaFixture(tb testing.TB, context string) (*dns.DNSKEY, *dns.RRSIG, []dns.RR) {
	tb.Helper()
	private, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		tb.Fatalf("generate: %v", err)
	}
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Flags: 257, Protocol: 3, Algorithm: MLDSA44,
		PublicKey: base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()),
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
		TypeCovered: dns.TypeA, Algorithm: MLDSA44, Labels: 3, OrigTtl: 300,
		Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // test epoch fits
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),     //nolint:gosec // test epoch fits
		KeyTag:     key.KeyTag(), SignerName: key.Hdr.Name,
	}
	signed, err := rrsigSignedData(sig, rrset)
	if err != nil {
		tb.Fatalf("signed data: %v", err)
	}
	raw, err := private.Sign(nil, signed, &mldsa.Options{Context: context})
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}
	sig.Signature = base64.StdEncoding.EncodeToString(raw)
	return key, sig, rrset
}

func TestMLDSA44Verifies(t *testing.T) {
	if !mldsa44Available {
		t.Skip("this build's crypto/mldsa does not verify")
	}
	key, sig, rrset := mldsaFixture(t, "")
	if err := cryptoVerify(key, sig, rrset); err != nil {
		t.Fatalf("a valid ML-DSA-44 signature did not verify: %v", err)
	}
}

// Every way a signature can fail to vouch for the data is a bad signature,
// and a key that is not an ML-DSA-44 key is not one, the distinction the
// EDE a client is told rests on.
func TestMLDSA44Refuses(t *testing.T) {
	if !mldsa44Available {
		t.Skip("this build's crypto/mldsa does not verify")
	}
	cases := []struct {
		name  string
		setup func(t *testing.T) (*dns.DNSKEY, *dns.RRSIG, []dns.RR)
		want  error
	}{
		{"a record changed", func(t *testing.T) (*dns.DNSKEY, *dns.RRSIG, []dns.RR) {
			key, sig, rrset := mldsaFixture(t, "")
			rrset[1] = mustSignatureRR(t, "www.example.com. 300 IN A 192.0.2.99")
			return key, sig, rrset
		}, dns.ErrSig},
		{"signed with a context", func(t *testing.T) (*dns.DNSKEY, *dns.RRSIG, []dns.RR) {
			// The draft fixes the context as empty; a signature bound to any
			// other context is not a DNSSEC signature.
			return mldsaFixture(t, "dnssec")
		}, dns.ErrSig},
		{"signature one octet short", func(t *testing.T) (*dns.DNSKEY, *dns.RRSIG, []dns.RR) {
			key, sig, rrset := mldsaFixture(t, "")
			raw, _ := base64.StdEncoding.DecodeString(sig.Signature)
			sig.Signature = base64.StdEncoding.EncodeToString(raw[:len(raw)-1])
			return key, sig, rrset
		}, dns.ErrSig},
		{"key one octet short", func(t *testing.T) (*dns.DNSKEY, *dns.RRSIG, []dns.RR) {
			key, sig, rrset := mldsaFixture(t, "")
			raw, _ := base64.StdEncoding.DecodeString(key.PublicKey)
			key.PublicKey = base64.StdEncoding.EncodeToString(raw[:len(raw)-1])
			sig.KeyTag = key.KeyTag()
			return key, sig, rrset
		}, ErrMissingDNSKEY},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, sig, rrset := tc.setup(t)
			if err := cryptoVerify(key, sig, rrset); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// The chain through the exported checks the resolver uses: the parent's DS
// authenticates the ML-DSA-44 key, and the key's signature authenticates
// the answer. Beside it, an answer carrying a broken P-256 signature and a
// good ML-DSA-44 one is secure, one signature that verifies is enough
// (RFC 6840 §5.11), the case where only the post-quantum path is intact.
func TestMLDSA44Chain(t *testing.T) {
	if !mldsa44Available {
		t.Skip("this build's crypto/mldsa does not verify")
	}
	key, sig, rrset := mldsaFixture(t, "")
	keys := map[uint16][]*dns.DNSKEY{key.KeyTag(): {key}}

	if unsupportedOnly, err := VerifyDS(keys, []dns.RR{key.ToDS(dns.SHA256)}); err != nil || unsupportedOnly {
		t.Fatalf("VerifyDS = (%v, %v), want the ML-DSA-44 key authenticated", unsupportedOnly, err)
	}

	answer := func(sigs ...dns.RR) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("www.example.com.", dns.TypeA)
		m.Answer = append(append([]dns.RR{}, rrset...), sigs...)
		return m
	}
	if ok, err := VerifyRRSIG("example.com.", keys, answer(sig)); !ok || err != nil {
		t.Fatalf("VerifyRRSIG = (%v, %v) for an ML-DSA-44 signed answer", ok, err)
	}

	var p256 signatureFixture
	for _, f := range signatureFixtures(t) {
		if f.name == "ECDSAP256SHA256" {
			p256 = f
		}
	}
	broken := dns.Copy(p256.sig).(*dns.RRSIG)
	raw, _ := base64.StdEncoding.DecodeString(broken.Signature)
	raw[0] ^= 0xff
	broken.Signature = base64.StdEncoding.EncodeToString(raw)
	keys[p256.key.KeyTag()] = append(keys[p256.key.KeyTag()], p256.key)

	if ok, err := VerifyRRSIG("example.com.", keys, answer(broken, sig)); !ok || err != nil {
		t.Fatalf("VerifyRRSIG = (%v, %v) with a good ML-DSA-44 signature beside a broken P-256 one", ok, err)
	}
	if ok, _ := VerifyRRSIG("example.com.", keys, answer(broken)); ok {
		t.Fatal("the broken P-256 signature verified on its own; the case above proves nothing")
	}
}

// A DS for an ML-DSA-44 key is usable, so a zone signed with it validates
// instead of being set aside as insecure, and so does one signed with it
// and a classic algorithm whose own path is broken (RFC 6840 §5.11).
func TestMLDSA44IsSupported(t *testing.T) {
	if !mldsa44Available {
		t.Skip("this build's crypto/mldsa does not verify")
	}
	if !IsSupportedDNSKEYAlgorithm(MLDSA44) {
		t.Fatal("ML-DSA-44 DNSKEYs are treated as unsupported")
	}
	key, _, _ := mldsaFixture(t, "")
	ds := key.ToDS(dns.SHA256)
	if ds == nil || !IsSupportedDS(ds) {
		t.Fatal("a SHA-256 DS for an ML-DSA-44 key is treated as unusable")
	}
}
