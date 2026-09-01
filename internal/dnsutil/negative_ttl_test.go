package dnsutil

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// denial builds a negative response whose SOA carries the given header TTL and
// MINIMUM field. RFC 2308 §5 derives the negative lifetime from the smaller of
// the two, so every test below fixes one and varies the other.
func denial(rcode int, soaTTL, soaMin uint32, extra ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.Rcode = rcode
	msg.Ns = append([]dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "example.org.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    soaTTL,
			},
			Ns:     "ns1.example.org.",
			Mbox:   "hostmaster.example.org.",
			Minttl: soaMin,
		},
	}, extra...)
	return msg
}

// TestNegativeTTLIsACeilingNotAFloor is the core of the RFC 2308 §5 contract:
// the SOA-derived lifetime says how long a resolver *may* cache the denial, so
// a value below the cache's own minimum has to survive intact. Four seconds
// either side of MinCacheTTL, and zero, which means the zone granted nothing.
func TestNegativeTTLIsACeilingNotAFloor(t *testing.T) {
	// Both fields are exercised, and each case pins the other high so the
	// value under test is unambiguously the one that won.
	const high = 86400

	for _, respType := range []ResponseType{TypeNXDomain, TypeNoRecords} {
		rcode := dns.RcodeNameError
		name := "NXDOMAIN"
		if respType == TypeNoRecords {
			rcode = dns.RcodeSuccess
			name = "NODATA"
		}

		for _, seconds := range []uint32{0, 1, 4, 5} {
			want := time.Duration(seconds) * time.Second

			t.Run(name+"/MINIMUM", func(t *testing.T) {
				got := CalculateCacheTTL(denial(rcode, high, seconds), respType)
				if got != want {
					t.Errorf("SOA MINIMUM %ds: got %v, want %v", seconds, got, want)
				}
			})

			t.Run(name+"/header TTL", func(t *testing.T) {
				got := CalculateCacheTTL(denial(rcode, seconds, high), respType)
				if got != want {
					t.Errorf("SOA header TTL %ds: got %v, want %v", seconds, got, want)
				}
			})
		}
	}
}

// TestNegativeTTLTakesTheSmallerSOAField is the rest of RFC 2308 §5: neither
// field is authoritative alone. A test that only varied MINIMUM would pass
// against an implementation that ignored the header TTL entirely.
func TestNegativeTTLTakesTheSmallerSOAField(t *testing.T) {
	if got, want := CalculateCacheTTL(denial(dns.RcodeNameError, 1, 4), TypeNXDomain), time.Second; got != want {
		t.Errorf("header TTL 1s vs MINIMUM 4s: got %v, want %v", got, want)
	}
	if got, want := CalculateCacheTTL(denial(dns.RcodeNameError, 4, 1), TypeNXDomain), time.Second; got != want {
		t.Errorf("header TTL 4s vs MINIMUM 1s: got %v, want %v", got, want)
	}
}

// TestPositiveTTLKeepsTheFloor is the other half of the contract. The floor is
// the resolver's own freshness policy for data a zone published normally, and
// nothing about the negative change may reach it.
func TestPositiveTTLKeepsTheFloor(t *testing.T) {
	answer := func(ttl uint32) *dns.Msg {
		msg := new(dns.Msg)
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.org.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				A: []byte{192, 0, 2, 1},
			},
		}
		return msg
	}

	for _, seconds := range []uint32{0, 1, 4} {
		if got := CalculateCacheTTL(answer(seconds), TypeSuccess); got != MinCacheTTL {
			t.Errorf("positive answer with %ds TTL: got %v, want the %v floor", seconds, got, MinCacheTTL)
		}
	}
	if got, want := CalculateCacheTTL(answer(5), TypeSuccess), MinCacheTTL; got != want {
		t.Errorf("positive answer at the floor: got %v, want %v", got, want)
	}
	if got, want := CalculateCacheTTL(answer(60), TypeSuccess), time.Minute; got != want {
		t.Errorf("positive answer above the floor: got %v, want %v", got, want)
	}
}

// TestFailureTTLUnchanged pins the SERVFAIL lifetime, which is neither derived
// from a zone nor floored, and must not move with the negative change.
func TestFailureTTLUnchanged(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeServerFailure
	if got, want := CalculateCacheTTL(msg, TypeServerFailure), 30*time.Second; got != want {
		t.Errorf("SERVFAIL: got %v, want %v", got, want)
	}
}

// TestDenialWithoutSOAIsNotCacheable covers RFC 2308 §5's other rule: with no
// SOA there is nothing to derive a lifetime from, and a denial cached anyway
// is what lets two misconfigured servers loop it between them.
func TestDenialWithoutSOAIsNotCacheable(t *testing.T) {
	bare := new(dns.Msg)
	bare.Rcode = dns.RcodeNameError
	if got := CalculateCacheTTL(bare, TypeNXDomain); got != 0 {
		t.Errorf("NXDOMAIN with no records: got %v, want 0", got)
	}
}

// TestDenialNeverOutlivesItsSignature is the reason the floor mattered beyond
// freshness: an entry served past its RRSIG expiration is bogus to every
// downstream validator (RFC 4035 §5.3.3), and the floor was the only thing
// still granting it time.
func TestDenialNeverOutlivesItsSignature(t *testing.T) {
	now := time.Now()
	sig := func(expiresIn time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   "example.org.",
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    86400,
			},
			OrigTtl:    86400,
			Expiration: uint32(now.Add(expiresIn).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
		}
	}

	// A signature with one second left bounds the denial at one second, even
	// though that is below the cache's minimum.
	msg := denial(dns.RcodeNameError, 86400, 86400, sig(time.Second))
	if got := CalculateCacheTTL(msg, TypeNXDomain); got > time.Second {
		t.Errorf("signature expiring in 1s: got %v, want at most 1s", got)
	}

	// An already-lapsed signature bounds it at nothing.
	msg = denial(dns.RcodeNameError, 86400, 86400, sig(-time.Hour))
	if got := CalculateCacheTTL(msg, TypeNXDomain); got != 0 {
		t.Errorf("expired signature: got %v, want 0", got)
	}
}

// TestNegativeTTLStillCapped keeps the upper bound honest: dropping the floor
// must not drop the maximum with it.
func TestNegativeTTLStillCapped(t *testing.T) {
	huge := uint32((MaxCacheTTL * 10).Seconds())
	if got, want := CalculateCacheTTL(denial(dns.RcodeNameError, huge, huge), TypeNXDomain), MaxCacheTTL; got != want {
		t.Errorf("oversized SOA: got %v, want the %v cap", got, want)
	}
}
