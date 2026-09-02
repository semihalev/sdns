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

// cnameTo builds an alias record for the chain fixtures below.
func cnameTo(name, target string, ttl uint32) dns.RR {
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Target: target,
	}
}

func askedFor(msg *dns.Msg, qtype uint16) *dns.Msg {
	msg.Question = []dns.Question{{
		Name:   "alias.example.org.",
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}}
	return msg
}

// TestAliasChainEndingInNodataIsNegative covers the commonest denial shape on
// the wire: the answer section carries a CNAME chain that never reaches the
// type asked for, and the terminal SOA is what says how long that holds.
// Reading the alias TTL instead treated the whole thing as an ordinary answer,
// so the SOA's MINIMUM was never consulted and the positive floor applied.
func TestAliasChainEndingInNodataIsNegative(t *testing.T) {
	build := func(soaMin uint32) *dns.Msg {
		msg := askedFor(new(dns.Msg), dns.TypeA)
		msg.Answer = []dns.RR{cnameTo("alias.example.org.", "target.example.org.", 300)}
		msg.Ns = denial(dns.RcodeSuccess, 300, soaMin).Ns
		return msg
	}

	for _, seconds := range []uint32{0, 1, 4, 5} {
		msg := build(seconds)

		mt, _ := ClassifyResponse(msg, time.Now())
		if mt != TypeNoRecords {
			t.Fatalf("SOA MINIMUM %ds: classified %v, want TypeNoRecords", seconds, mt)
		}

		want := time.Duration(seconds) * time.Second
		if got := CalculateCacheTTL(msg, mt); got != want {
			t.Errorf("SOA MINIMUM %ds: got %v, want %v", seconds, got, want)
		}
	}

	// A chain that does reach the type asked for is an ordinary answer, and
	// keeps the floor. Without this the fix would swallow every alias.
	resolved := askedFor(new(dns.Msg), dns.TypeA)
	resolved.Answer = []dns.RR{
		cnameTo("alias.example.org.", "target.example.org.", 300),
		&dns.A{
			Hdr: dns.RR_Header{Name: "target.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   []byte{192, 0, 2, 1},
		},
	}
	if mt, _ := ClassifyResponse(resolved, time.Now()); mt != TypeSuccess {
		t.Fatalf("a resolved alias classified %v, want TypeSuccess", mt)
	}

	// An explicit CNAME question is answered by the CNAME itself.
	asked := askedFor(new(dns.Msg), dns.TypeCNAME)
	asked.Answer = []dns.RR{cnameTo("alias.example.org.", "target.example.org.", 300)}
	asked.Ns = denial(dns.RcodeSuccess, 300, 1).Ns
	if mt, _ := ClassifyResponse(asked, time.Now()); mt != TypeSuccess {
		t.Fatalf("an explicit CNAME question classified %v, want TypeSuccess", mt)
	}
}

// TestDenialWithoutSOAIsNotCacheableInAnyShape is the rest of RFC 2308 §5. The
// check has to look for the SOA itself: a denial carrying an alias chain and
// no SOA is full of records and still says nothing about how long it holds.
func TestDenialWithoutSOAIsNotCacheableInAnyShape(t *testing.T) {
	withAlias := askedFor(new(dns.Msg), dns.TypeA)
	withAlias.Rcode = dns.RcodeNameError
	withAlias.Answer = []dns.RR{cnameTo("alias.example.org.", "target.example.org.", 60)}
	if got := CalculateCacheTTL(withAlias, TypeNXDomain); got != 0 {
		t.Errorf("NXDOMAIN carrying an alias and no SOA: got %v, want 0", got)
	}

	// Nothing at all is not a denial anyone can cache either, and it must not
	// arrive at the positive floor by way of TypeSuccess.
	bare := askedFor(new(dns.Msg), dns.TypeA)
	if mt, _ := ClassifyResponse(bare, time.Now()); mt != TypeNotCacheable {
		t.Errorf("empty NOERROR with no SOA classified %v, want TypeNotCacheable", mt)
	}
}

// TestSignatureBoundsAreHard is RFC 4035 §5.3.3: the served lifetime may not
// exceed the smallest of the RRSIG's header TTL, its Original TTL, and the
// time left before it expires. Neither the record TTLs nor the cache's own
// floor may lift it past that.
func TestSignatureBoundsAreHard(t *testing.T) {
	now := time.Now()
	sig := func(hdrTTL, origTTL uint32, expiresIn time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:        dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdrTTL},
			OrigTtl:    origTTL,
			Expiration: uint32(now.Add(expiresIn).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
		}
	}

	// Original TTL is a bound in its own right. Reading only the header TTL
	// let a denial whose signature authorised one second live for an hour.
	msg := denial(dns.RcodeNameError, 86400, 86400, sig(86400, 1, time.Hour))
	if got, want := CalculateCacheTTL(msg, TypeNXDomain), time.Second; got != want {
		t.Errorf("RRSIG OrigTtl 1s: got %v, want %v", got, want)
	}

	// The positive floor may not lift a signature bound. A signature with two
	// seconds left bounds the answer at two seconds, floor or no floor.
	positive := askedFor(new(dns.Msg), dns.TypeA)
	positive.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "alias.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		},
		sig(3600, 3600, 2*time.Second),
	}
	if got := CalculateCacheTTL(positive, TypeSuccess); got > 2*time.Second {
		t.Errorf("positive answer with a 2s signature: got %v, want at most 2s", got)
	}

	// Unsigned data still takes the floor, which is the whole point of keeping
	// the two bounds apart.
	unsigned := askedFor(new(dns.Msg), dns.TypeA)
	unsigned.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "alias.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   []byte{192, 0, 2, 1},
	}}
	if got, want := CalculateCacheTTL(unsigned, TypeSuccess), MinCacheTTL; got != want {
		t.Errorf("unsigned one-second answer: got %v, want the %v floor", got, want)
	}
}
