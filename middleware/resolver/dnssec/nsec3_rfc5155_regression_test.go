package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestVerifyNameErrorForZoneWithWorkOptOutIsInsecure(t *testing.T) {
	const (
		qname = "missing.example."
		zone  = "example."
	)
	closest, nextCloser, wildcard := aggressiveTestNSEC3NameError(t, qname, zone)
	nextCloser.Flags = 1

	msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	secure, err := VerifyNameErrorForZoneWithWork(
		msg,
		[]dns.RR{closest, nextCloser, wildcard},
		zone,
		nil,
	)
	if err != nil {
		t.Fatalf("valid Opt-Out NXDOMAIN proof rejected: %v", err)
	}
	if secure {
		t.Fatal("Opt-Out next-closer proof reported secure; RFC 5155 requires AD to be cleared")
	}
}

func TestVerifyNameErrorForZoneWithWorkRejectsInvalidClosestEncloser(t *testing.T) {
	const (
		qname = "missing.example."
		zone  = "example."
	)

	tests := []struct {
		name   string
		bitmap []uint16
	}{
		{
			name:   "DNAME exists",
			bitmap: []uint16{dns.TypeDNAME},
		},
		{
			name:   "delegation is not a closest encloser",
			bitmap: []uint16{dns.TypeNS},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closest, nextCloser, wildcard := aggressiveTestNSEC3NameError(t, qname, zone)
			closest.TypeBitMap = tt.bitmap

			msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
			msg.Rcode = dns.RcodeNameError
			if _, err := VerifyNameErrorForZoneWithWork(
				msg,
				[]dns.RR{closest, nextCloser, wildcard},
				zone,
				nil,
			); err != ErrNSECBadDelegation {
				t.Fatalf("closest-encloser bitmap %v: error = %v, want %v",
					tt.bitmap, err, ErrNSECBadDelegation)
			}
		})
	}
}

func TestNSEC3ForZonePreflightRejectsUnsafeOrUnboundChains(t *testing.T) {
	const (
		qname = "missing.example."
		zone  = "example."
	)

	t.Run("mixed parameters cannot assemble one proof", func(t *testing.T) {
		closest, nextCloser, wildcard := aggressiveTestNSEC3NameError(t, qname, zone)
		nextCloser.Iterations++

		msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
		msg.Rcode = dns.RcodeNameError
		if _, err := VerifyNameErrorForZoneWithWork(
			msg,
			[]dns.RR{closest, nextCloser, wildcard},
			zone,
			nil,
		); err != ErrNSECMissingCoverage {
			t.Fatalf("mixed-parameter proof error = %v, want %v", err, ErrNSECMissingCoverage)
		}
	})

	t.Run("undefined flags are ignored", func(t *testing.T) {
		exact := aggressiveTestNSEC3Match(t, qname, zone, nil)
		exact.Flags = 2

		msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
		if _, err := VerifyNODATAForZoneWithWork(
			msg,
			[]dns.RR{exact},
			zone,
			nil,
		); err != ErrNSECMissingCoverage {
			t.Fatalf("undefined-flags proof error = %v, want %v", err, ErrNSECMissingCoverage)
		}
	})

	t.Run("owner is exactly one hash label below signer", func(t *testing.T) {
		exact := aggressiveTestNSEC3Match(t, qname, zone, nil)
		exact.Hdr.Name = exact.Hdr.Name[:len(exact.Hdr.Name)-len(zone)] + "extra." + zone

		msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
		if _, err := VerifyNODATAForZoneWithWork(
			msg,
			[]dns.RR{exact},
			zone,
			nil,
		); err != ErrNSECMissingCoverage {
			t.Fatalf("extra-owner-label proof error = %v, want %v", err, ErrNSECMissingCoverage)
		}
	})
}

func TestBaseNSEC3HashUsesDNSASCIIWireCanonicalization(t *testing.T) {
	const zone = "example."
	exactASCII := aggressiveTestNSEC3Match(t, "k.example.", zone, nil)

	t.Run("escaped uppercase ASCII folds after unpacking", func(t *testing.T) {
		msg := new(dns.Msg).SetQuestion(`\075.example.`, dns.TypeA)
		secure, err := VerifyNODATAForZoneWithWork(
			msg,
			[]dns.RR{exactASCII},
			zone,
			nil,
		)
		if err != nil {
			t.Fatalf("escaped ASCII exact-match NODATA rejected: %v", err)
		}
		if !secure {
			t.Fatal("ordinary exact-match NODATA unexpectedly reported insecure")
		}
	})

	t.Run("Unicode Kelvin sign does not alias ASCII k", func(t *testing.T) {
		msg := new(dns.Msg).SetQuestion("\u212A.example.", dns.TypeA)
		if _, err := VerifyNODATAForZoneWithWork(
			msg,
			[]dns.RR{exactASCII},
			zone,
			nil,
		); err != ErrNSECMissingCoverage {
			t.Fatalf("Kelvin-sign alias error = %v, want %v", err, ErrNSECMissingCoverage)
		}
	})
}
