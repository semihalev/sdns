package dnsutil

import (
	"fmt"
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

// TestSiblingSignatureKeepsTheRRsetAlive is the key-rollover case. An RRset
// carries a signature from the outgoing key beside one from the incoming key
// for as long as the rollover takes, and the outgoing one lapses first.
//
// Judging the message on the worst signature anywhere in it condemned every
// such answer: AD stripped, lifetime zero, admission refused, while the
// resolver's own validator (dnssec.VerifyRRSIG) was correctly accepting the
// RRset on the strength of the sibling.
func TestSiblingSignatureKeepsTheRRsetAlive(t *testing.T) {
	now := time.Now()
	sig := func(owner string, covered uint16, tag uint16, expiresIn time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: covered,
			OrigTtl:     3600,
			KeyTag:      tag,
			Expiration:  uint32(now.Add(expiresIn).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
		}
	}
	answer := func() dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: "x.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		}
	}
	ask := func(build func(*dns.Msg)) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("x.example.org.", dns.TypeA)
		build(msg)
		return msg
	}

	t.Run("a lapsed sibling condemns nothing", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{
				answer(),
				sig("x.example.org.", dns.TypeA, 111, -time.Hour),
				sig("x.example.org.", dns.TypeA, 222, time.Hour),
			}
		})
		if HasExpiredSignatures(msg, now) {
			t.Error("an RRset with a live signature was reported as lapsed")
		}
		mt, _ := ClassifyResponse(msg, now)
		if mt != TypeSuccess {
			t.Errorf("classified %v, want TypeSuccess", mt)
		}
		// Bounded by the sibling that is still good, not by the one that is not.
		if got := CalculateCacheTTL(msg, mt); got < 59*time.Minute {
			t.Errorf("lifetime %v, want the live sibling's hour", got)
		}
	})

	t.Run("the same during a denial", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns.example.org.", Mbox: "hostmaster.example.org.", Minttl: 300,
				},
				sig("example.org.", dns.TypeSOA, 111, -time.Hour),
				sig("example.org.", dns.TypeSOA, 222, time.Hour),
			}
		})
		if HasExpiredSignatures(msg, now) {
			t.Error("a denial with a live signature was reported as lapsed")
		}
		if got, want := CalculateCacheTTL(msg, TypeNXDomain), 5*time.Minute; got != want {
			t.Errorf("lifetime %v, want the SOA's %v", got, want)
		}
	})

	t.Run("every sibling lapsed is still lapsed", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{
				answer(),
				sig("x.example.org.", dns.TypeA, 111, -time.Hour),
				sig("x.example.org.", dns.TypeA, 222, -time.Minute),
			}
		})
		if !HasExpiredSignatures(msg, now) {
			t.Error("an RRset with nothing left covering it was reported as usable")
		}
	})

	t.Run("siblings are per RRset, not per message", func(t *testing.T) {
		// The A RRset is covered; the AAAA RRset beside it is not. A live
		// signature over one does not vouch for the other.
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{
				answer(),
				sig("x.example.org.", dns.TypeA, 222, time.Hour),
				&dns.AAAA{Hdr: dns.RR_Header{
					Name: "x.example.org.", Rrtype: dns.TypeAAAA,
					Class: dns.ClassINET, Ttl: 3600,
				}},
				sig("x.example.org.", dns.TypeAAAA, 111, -time.Hour),
			}
		})
		if !HasExpiredSignatures(msg, now) {
			t.Error("an uncovered RRset was excused by a sibling covering a different type")
		}
	})

	t.Run("the additional section does not withdraw AD", func(t *testing.T) {
		// AD is a statement about the answer and authority sections
		// (RFC 4035 §3.2.3). A lapsed signature over glue is not grounds for
		// taking it back.
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{answer(), sig("x.example.org.", dns.TypeA, 222, time.Hour)}
			m.Extra = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{
					Name: "ns.example.org.", Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 3600,
				}},
				sig("ns.example.org.", dns.TypeA, 111, -time.Hour),
			}
		})
		if HasExpiredSignatures(msg, now) {
			t.Error("a lapsed glue signature withdrew AD from the answer")
		}
	})
}

// TestSiblingIdentityAndValidity pins what makes two signatures siblings and
// what makes one usable. A signature vouches for an RRset only while the
// current time sits inside both of its bounds (RFC 4035 §5.3.1), only for
// the RRset its signer owns (§5.3.2), and only in the section it arrived in.
// Among usable siblings the shortest lifetime wins whichever order the wire
// put them in, and a lapsed signature over glue bounds nothing.
func TestSiblingIdentityAndValidity(t *testing.T) {
	now := time.Now()
	sig := func(owner, signer string, covered uint16, origTTL uint32, from, until time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: covered,
			OrigTtl:     origTTL,
			SignerName:  signer,
			Inception:   uint32(now.Add(from).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration:  uint32(now.Add(until).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}
	a := func(owner string) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		}
	}
	ask := func(build func(*dns.Msg)) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("x.example.org.", dns.TypeA)
		build(msg)
		return msg
	}

	t.Run("a signature whose inception has not arrived covers nothing", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{
				a("x.example.org."),
				sig("x.example.org.", "example.org.", dns.TypeA, 3600, -2*time.Hour, -time.Hour),
				sig("x.example.org.", "example.org.", dns.TypeA, 3600, time.Hour, 2*time.Hour),
			}
		})
		if !HasExpiredSignatures(msg, now) {
			t.Error("a future signature rescued an RRset whose only other signature had lapsed")
		}
		if mt, _ := ClassifyResponse(msg, now); mt != TypeExpiredSignature {
			t.Errorf("classified %v, want TypeExpiredSignature", mt)
		}
		if got := CalculateCacheTTL(msg, TypeSuccess); got != 0 {
			t.Errorf("lifetime %v, want nothing: no signature is valid now", got)
		}
	})

	t.Run("a sibling under another signer covers nothing", func(t *testing.T) {
		// At a delegation the parent's NSEC over the child's name and the
		// child's apex NSEC share owner, class and type. The parent's proof
		// has lapsed; the child's live signature is not its sibling.
		msg := ask(func(m *dns.Msg) {
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns.example.org.", Mbox: "hostmaster.example.org.", Minttl: 300,
				},
				sig("example.org.", "example.org.", dns.TypeSOA, 300, -2*time.Hour, time.Hour),
				&dns.NSEC{
					Hdr:        dns.RR_Header{Name: "child.example.org.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
					NextDomain: "d.example.org.",
					TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
				},
				sig("child.example.org.", "example.org.", dns.TypeNSEC, 300, -2*time.Hour, -time.Hour),
				sig("child.example.org.", "child.example.org.", dns.TypeNSEC, 300, -2*time.Hour, time.Hour),
			}
		})
		if !HasExpiredSignatures(msg, now) {
			t.Error("the child's live signature excused the parent's lapsed proof")
		}
		if got := CalculateCacheTTL(msg, TypeNXDomain); got != 0 {
			t.Errorf("lifetime %v, want nothing: the proof's own signature lapsed", got)
		}
	})

	t.Run("a sibling in another section covers nothing", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{
				a("x.example.org."),
				sig("x.example.org.", "example.org.", dns.TypeA, 3600, -2*time.Hour, time.Hour),
			}
			m.Ns = []dns.RR{
				a("x.example.org."),
				sig("x.example.org.", "example.org.", dns.TypeA, 3600, -2*time.Hour, -time.Hour),
			}
		})
		if !HasExpiredSignatures(msg, now) {
			t.Error("a live answer signature excused the same RRset's lapsed copy in the authority section")
		}
		if got := CalculateCacheTTL(msg, TypeSuccess); got != 0 {
			t.Errorf("lifetime %v, want nothing: an authority RRset is uncovered", got)
		}
	})

	t.Run("a zero and an hour bound the same whichever comes first", func(t *testing.T) {
		zero := sig("x.example.org.", "example.org.", dns.TypeA, 0, -2*time.Hour, time.Hour)
		hour := sig("x.example.org.", "example.org.", dns.TypeA, 3600, -2*time.Hour, time.Hour)
		for name, order := range map[string][]dns.RR{
			"zero first": {a("x.example.org."), zero, hour},
			"hour first": {a("x.example.org."), hour, zero},
		} {
			msg := ask(func(m *dns.Msg) { m.Answer = order })
			if HasExpiredSignatures(msg, now) {
				t.Errorf("%s: both signatures are valid, yet the RRset was reported lapsed", name)
			}
			if got := CalculateCacheTTL(msg, TypeSuccess); got != 0 {
				t.Errorf("%s: lifetime %v, want nothing: a sibling authorises no lifetime", name, got)
			}
		}
	})

	t.Run("a lapsed signature over glue does not zero the answer", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{
				a("x.example.org."),
				sig("x.example.org.", "example.org.", dns.TypeA, 3600, -2*time.Hour, time.Hour),
			}
			m.Extra = []dns.RR{
				a("ns.example.org."),
				sig("ns.example.org.", "example.org.", dns.TypeA, 3600, -2*time.Hour, -time.Hour),
			}
		})
		if got := CalculateCacheTTL(msg, TypeSuccess); got < 59*time.Minute {
			t.Errorf("lifetime %v, want the answer's own hour: glue is not the answer", got)
		}
	})
}

// TestSignatureHeaderTTLBoundsOnlyWhileUsable pins the record scan: a
// signature's header TTL reaches the lifetime only through the usable
// signature it belongs to. A lapsed sibling, or a glue signature, carrying a
// header TTL of zero used to zero an answer whose live signature permitted an
// hour.
func TestSignatureHeaderTTLBoundsOnlyWhileUsable(t *testing.T) {
	now := time.Now()
	sig := func(owner string, hdrTTL uint32, until time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdrTTL},
			TypeCovered: dns.TypeA,
			OrigTtl:     3600,
			SignerName:  "example.org.",
			Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration:  uint32(now.Add(until).Unix()),          //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}
	a := func(owner string) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		}
	}
	ask := func(build func(*dns.Msg)) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("x.example.org.", dns.TypeA)
		build(msg)
		return msg
	}

	t.Run("a lapsed sibling's header TTL bounds nothing", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{
				a("x.example.org."),
				sig("x.example.org.", 0, -time.Hour),
				sig("x.example.org.", 3600, time.Hour),
			}
		})
		if HasExpiredSignatures(msg, now) {
			t.Error("a live sibling covers the RRset, yet it was reported lapsed")
		}
		if got := CalculateCacheTTL(msg, TypeSuccess); got < 59*time.Minute {
			t.Errorf("lifetime %v, want the live sibling's hour, not the lapsed one's zero header", got)
		}
	})

	t.Run("a glue signature's header TTL bounds nothing", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{a("x.example.org."), sig("x.example.org.", 3600, time.Hour)}
			m.Extra = []dns.RR{a("ns.example.org."), sig("ns.example.org.", 0, time.Hour)}
		})
		if got := CalculateCacheTTL(msg, TypeSuccess); got < 59*time.Minute {
			t.Errorf("lifetime %v, want the answer's hour: glue signatures do not bound it", got)
		}
	})

	t.Run("a live signature's own header TTL still bounds", func(t *testing.T) {
		msg := ask(func(m *dns.Msg) {
			m.Answer = []dns.RR{a("x.example.org."), sig("x.example.org.", 30, time.Hour)}
		})
		if got, want := CalculateCacheTTL(msg, TypeSuccess), 30*time.Second; got != want {
			t.Errorf("lifetime %v, want the signature's %v header TTL", got, want)
		}
	})
}

// TestEachSignedRRsetCostsNothingOnTheCommonPath pins the walk's price where
// it runs several times per miss: an ordinary response, one or a few signed
// RRsets, is grouped in place without allocating. Past the inline capacity
// the walk indexes through a map and must still report every RRset exactly
// once, with siblings that arrive after the switch matched to their RRset.
func TestEachSignedRRsetCostsNothingOnTheCommonPath(t *testing.T) {
	now := time.Now()
	sig := func(owner string, tag uint16, until time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA,
			OrigTtl:     3600,
			KeyTag:      tag,
			SignerName:  "example.org.",
			Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration:  uint32(now.Add(until).Unix()),          //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}

	t.Run("a rollover answer allocates nothing", func(t *testing.T) {
		answer := []dns.RR{
			sig("x.example.org.", 111, -time.Hour),
			sig("x.example.org.", 222, time.Hour),
		}
		authority := []dns.RR{sig("example.org.", 333, time.Hour)}
		reported := 0
		allocs := testing.AllocsPerRun(100, func() {
			reported = 0
			eachSignedRRset([][]dns.RR{answer, authority}, now, func(bool, time.Duration) { reported++ })
		})
		if allocs != 0 {
			t.Errorf("common path allocated %v times per walk, want none", allocs)
		}
		if reported != 2 {
			t.Errorf("reported %d RRsets, want 2", reported)
		}
	})

	t.Run("past the inline capacity every RRset is still reported once", func(t *testing.T) {
		const n = signedRRsetInline + 4
		var answer []dns.RR
		// Every lapsed signature first, then every live sibling: the live
		// half arrives after the walk has switched to the map, so each has
		// to find the RRset its lapsed sibling opened.
		for i := range n {
			answer = append(answer, sig(fmt.Sprintf("r%d.example.org.", i), 111, -time.Hour))
		}
		for i := range n {
			answer = append(answer, sig(fmt.Sprintf("R%d.EXAMPLE.ORG.", i), 222, time.Hour))
		}
		reported, lapsed := 0, 0
		eachSignedRRset([][]dns.RR{answer}, now, func(covered bool, usable time.Duration) {
			reported++
			if !covered {
				lapsed++
			}
			if usable < 59*time.Minute {
				t.Errorf("usable %v, want the live sibling's hour", usable)
			}
		})
		if reported != n {
			t.Errorf("reported %d RRsets, want %d", reported, n)
		}
		if lapsed != 0 {
			t.Errorf("%d RRsets reported lapsed after their live sibling arrived past the switch", lapsed)
		}
	})
}
