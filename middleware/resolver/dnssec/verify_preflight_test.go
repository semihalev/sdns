package dnssec

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

type releaseHookSignatureWork struct {
	countingVerifyWork
	onRelease func()
}

func (w *releaseHookSignatureWork) BeginSignature() (func(), error) {
	w.signatures++
	return func() {
		w.releases++
		if w.onRelease != nil {
			w.onRelease()
		}
	}, nil
}

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

	work := &countingVerifyWork{}
	var rrsetUsed uint32
	if err := verifyOneSigWithWork(
		map[uint16][]*dns.DNSKEY{sig.KeyTag: {key}},
		rrset,
		sig,
		work,
		&rrsetUsed,
	); err != ErrInvalidSignaturePeriod {
		t.Fatalf("verifyOneSig error = %v, want %v", err, ErrInvalidSignaturePeriod)
	}
	if work.signatures != 0 {
		t.Fatalf("expired signature reached %d crypto operations, want 0", work.signatures)
	}
}

// TestVerifyOneSigRejectsExpirationDuringCrypto pins the acceptance-time
// validity recheck. The work release hook advances the fixture from valid to
// expired after a successful public-key operation returns.
func TestVerifyOneSigRejectsExpirationDuringCrypto(t *testing.T) {
	material := newWorkFactorKey(t)
	rrset := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "expiry-race." + workFactorZone,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 9},
		},
	}
	now := time.Now()
	sig := signWorkFactorRRSet(t, material, rrset, now.Add(-time.Hour), now.Add(time.Hour))

	work := &releaseHookSignatureWork{}
	work.onRelease = func() {
		sig.Expiration = 2
		sig.Inception = 1
	}
	var rrsetUsed uint32
	if err := verifyOneSigWithWork(
		map[uint16][]*dns.DNSKEY{sig.KeyTag: {material.key}},
		rrset,
		sig,
		work,
		&rrsetUsed,
	); err != ErrInvalidSignaturePeriod {
		t.Fatalf("verifyOneSig error = %v, want %v", err, ErrInvalidSignaturePeriod)
	}
	if work.signatures != 1 {
		t.Fatalf("crypto operations = %d, want 1", work.signatures)
	}
	if work.releases != 1 {
		t.Fatalf("signature releases = %d, want 1", work.releases)
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
		if err := verifyOneSig(nil, rrset, sig); err != ErrMissingDNSKEY {
			t.Fatalf("verifyOneSig error = %v, want %v", err, ErrMissingDNSKEY)
		}
	})

	t.Run("signer mismatch", func(t *testing.T) {
		wrongSigner := *key
		wrongSigner.Hdr.Name = "other.example."
		keys := map[uint16][]*dns.DNSKEY{sig.KeyTag: {&wrongSigner}}
		if err := verifyOneSig(keys, rrset, sig); err != ErrMissingDNSKEY {
			t.Fatalf("verifyOneSig error = %v, want %v", err, ErrMissingDNSKEY)
		}
	})
}
