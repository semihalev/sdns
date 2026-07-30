package dnssec

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestVerifyOneSigRejectsExpiredBeforeCrypto pins the cheap-before-expensive
// ordering. The deliberately malformed signature would fail cryptoVerify if
// reached; an expired signature must instead be rejected by its metadata
// before any candidate-key cryptography is attempted.
func TestVerifyOneSigRejectsExpiredBeforeCrypto(t *testing.T) {
	key := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	rrset := []dns.RR{mustRR(t, mboxA)}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "mailbox.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  2,
		Inception:   1,
		KeyTag:      key.KeyTag(),
		SignerName:  key.Header().Name,
		Signature:   "not-valid-base64",
	}

	cryptoOps := 0
	if err := verifyOneSig(
		map[uint16][]*dns.DNSKEY{sig.KeyTag: {key}},
		rrset,
		sig,
		func(key *dns.DNSKEY, sig *dns.RRSIG, set []dns.RR) error {
			cryptoOps++
			return cryptoVerify(key, sig, set)
		},
	); err != ErrInvalidSignaturePeriod {
		t.Fatalf("verifyOneSig error = %v, want %v", err, ErrInvalidSignaturePeriod)
	}
	if cryptoOps != 0 {
		t.Fatalf("expired signature reached %d crypto operations, want 0", cryptoOps)
	}
}

// TestVerifyOneSigRejectsExpirationDuringCrypto pins the acceptance-time
// validity recheck. The injected verifier advances the fixture from valid to
// expired while representing a successful public-key operation.
func TestVerifyOneSigRejectsExpirationDuringCrypto(t *testing.T) {
	key := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	rrset := []dns.RR{mustRR(t, mboxA)}
	now := uint32(time.Now().Unix()) //nolint:gosec // DNSSEC timestamps are unsigned 32-bit serial values.
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "mailbox.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Expiration:  now + 300,
		Inception:   now - 300,
		KeyTag:      key.KeyTag(),
		SignerName:  key.Header().Name,
	}

	cryptoOps := 0
	if err := verifyOneSig(
		map[uint16][]*dns.DNSKEY{sig.KeyTag: {key}},
		rrset,
		sig,
		func(*dns.DNSKEY, *dns.RRSIG, []dns.RR) error {
			cryptoOps++
			sig.Expiration = 2
			sig.Inception = 1
			return nil
		},
	); err != ErrInvalidSignaturePeriod {
		t.Fatalf("verifyOneSig error = %v, want %v", err, ErrInvalidSignaturePeriod)
	}
	if cryptoOps != 1 {
		t.Fatalf("crypto operations = %d, want 1", cryptoOps)
	}
}

// TestVerifyOneSigExpiredPreservesMissingKeyPrecedence ensures the preflight
// optimization does not change the externally visible EDE when no candidate
// can authenticate the claimed signer. Signature period becomes relevant only
// after a signer-matching key exists.
func TestVerifyOneSigExpiredPreservesMissingKeyPrecedence(t *testing.T) {
	key := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	rrset := []dns.RR{mustRR(t, mboxA)}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "mailbox.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Expiration:  2,
		Inception:   1,
		KeyTag:      key.KeyTag(),
		SignerName:  key.Header().Name,
	}

	t.Run("key tag absent", func(t *testing.T) {
		if err := verifyOneSig(nil, rrset, sig, cryptoVerify); err != ErrMissingDNSKEY {
			t.Fatalf("verifyOneSig error = %v, want %v", err, ErrMissingDNSKEY)
		}
	})

	t.Run("signer mismatch", func(t *testing.T) {
		wrongSigner := *key
		wrongSigner.Hdr.Name = "other.example."
		keys := map[uint16][]*dns.DNSKEY{sig.KeyTag: {&wrongSigner}}
		if err := verifyOneSig(keys, rrset, sig, cryptoVerify); err != ErrMissingDNSKEY {
			t.Fatalf("verifyOneSig error = %v, want %v", err, ErrMissingDNSKEY)
		}
	})
}
