package dnssec

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signatureValidity names the side a validity period failed on, not yet
// valid (EDE 8) or expired (EDE 7), and agrees with the library's
// ValidityPeriod on whether it failed at all, serial arithmetic included.
func TestSignatureValidityNamesTheSide(t *testing.T) {
	now := uint32(time.Now().Unix()) //nolint:gosec // DNSSEC times are 32-bit serials
	hour := uint32(time.Hour / time.Second)
	for _, tc := range []struct {
		name                  string
		inception, expiration uint32
		want                  error
	}{
		{"valid", now - hour, now + hour, nil},
		{"not yet valid", now + hour, now + 2*hour, ErrSignatureNotYetValid},
		{"expired", now - 2*hour, now - hour, ErrInvalidSignaturePeriod},
		{"long expired, near zero", 1, 2, ErrInvalidSignaturePeriod},
		// Serial arithmetic: an inception almost half the 32-bit serial
		// space ahead is still in the future, not in the past.
		{"not yet valid, far ahead", now + 1<<31 - hour, now + 1<<31 - 1, ErrSignatureNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := &dns.RRSIG{Inception: tc.inception, Expiration: tc.expiration}
			got := signatureValidity(sig)
			if got != tc.want {
				t.Fatalf("signatureValidity = %v, want %v", got, tc.want)
			}
			if (got == nil) != sig.ValidityPeriod(time.Time{}) {
				t.Fatalf("disagrees with ValidityPeriod: %v against %v", got, sig.ValidityPeriod(time.Time{}))
			}
		})
	}
}

// A signature whose inception is ahead is refused as not yet valid, EDE 8,
// before any candidate-key cryptography, exactly as an expired one is
// refused as expired.
func TestVerifyOneSigRejectsNotYetValidBeforeCrypto(t *testing.T) {
	key := mustRR(t, mboxZSK7).(*dns.DNSKEY)
	rrset := []dns.RR{mustRR(t, mboxA)}
	now := uint32(time.Now().Unix()) //nolint:gosec // DNSSEC times are 32-bit serials
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "mailbox.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Labels:      2,
		OrigTtl:     300,
		Inception:   now + 3600,
		Expiration:  now + 7200,
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
	); err != ErrSignatureNotYetValid {
		t.Fatalf("verifyOneSig error = %v, want %v", err, ErrSignatureNotYetValid)
	}
	if work.signatures != 0 {
		t.Fatalf("a signature not yet valid reached %d crypto operations, want 0", work.signatures)
	}
}
