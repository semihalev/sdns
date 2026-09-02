package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

// TestClearDNSSECKeepsOnlyTheTypeAskedFor pins ClearDNSSEC's exception as
// RFC 4035 §3.2.1 states it: a DO=0 response carries no authenticating
// record it was not asked for, in any section, and the one type the question
// named is kept wherever it appears. A query for RRSIG keeps its signatures
// and loses the NSEC that came along as a proof; a query for NSEC keeps the
// NSEC and loses the signatures; an ordinary query loses all of them, the
// additional section included, and keeps the records they covered.
func TestClearDNSSECKeepsOnlyTheTypeAskedFor(t *testing.T) {
	rrsig := func(owner string, covered uint16) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: covered, SignerName: "example.",
		}
	}
	nsec := func(owner string) dns.RR {
		return &dns.NSEC{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "z.example."}
	}
	build := func(qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("mx.example.", qtype)
		m.Answer = []dns.RR{
			&dns.MX{Hdr: dns.RR_Header{Name: "mx.example.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "target.example."},
			rrsig("mx.example.", dns.TypeMX),
			nsec("mx.example."),
			rrsig("mx.example.", dns.TypeNSEC),
		}
		m.Ns = []dns.RR{nsec("example."), rrsig("example.", dns.TypeNSEC)}
		m.Extra = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "target.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}},
			rrsig("target.example.", dns.TypeA),
			nsec("target.example."),
		}
		return m
	}
	count := func(m *dns.Msg, rrtype uint16) int {
		n := 0
		for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
			for _, rr := range section {
				if rr.Header().Rrtype == rrtype {
					n++
				}
			}
		}
		return n
	}

	for _, tc := range []struct {
		name                            string
		qtype                           uint16
		wantRRSIG, wantNSEC, wantOthers int
	}{
		{"an ordinary question loses every authenticating record", dns.TypeMX, 0, 0, 2},
		{"a question for RRSIG keeps the signatures and nothing else", dns.TypeRRSIG, 4, 0, 2},
		{"a question for NSEC keeps the NSEC and nothing else", dns.TypeNSEC, 0, 3, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := ClearDNSSEC(build(tc.qtype))
			if got := count(m, dns.TypeRRSIG); got != tc.wantRRSIG {
				t.Errorf("%d RRSIG records kept, want %d", got, tc.wantRRSIG)
			}
			if got := count(m, dns.TypeNSEC); got != tc.wantNSEC {
				t.Errorf("%d NSEC records kept, want %d", got, tc.wantNSEC)
			}
			if got := count(m, dns.TypeMX) + count(m, dns.TypeA); got != tc.wantOthers {
				t.Errorf("%d covered records kept, want %d", got, tc.wantOthers)
			}
		})
	}
}

// TestClearDNSSECInPlaceMatchesAndAllocatesNothing pins the in-place
// variant to the same rule as ClearDNSSEC, compacting the message's own
// sections without allocating — it runs on every DO=0 aggressive hit.
func TestClearDNSSECInPlaceMatchesAndAllocatesNothing(t *testing.T) {
	build := func(qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("m.example.", qtype)
		m.Ns = []dns.RR{
			&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 300},
			&dns.RRSIG{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeSOA, SignerName: "example."},
			&dns.NSEC{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "z.example."},
			&dns.RRSIG{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeNSEC, SignerName: "example."},
		}
		return m
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC} {
		want := ClearDNSSEC(build(qtype))
		got := build(qtype)
		backing := &got.Ns[0]
		ClearDNSSECInPlace(got)
		if len(got.Ns) != len(want.Ns) {
			t.Fatalf("qtype %d: in place kept %d records, ClearDNSSEC kept %d", qtype, len(got.Ns), len(want.Ns))
		}
		for i := range got.Ns {
			if got.Ns[i].String() != want.Ns[i].String() {
				t.Fatalf("qtype %d: record %d differs: %v vs %v", qtype, i, got.Ns[i], want.Ns[i])
			}
		}
		if len(got.Ns) > 0 && &got.Ns[0] != backing {
			t.Fatalf("qtype %d: in place did not compact the message's own slice", qtype)
		}
	}

	m := build(dns.TypeA)
	if allocs := testing.AllocsPerRun(100, func() {
		m.Ns = m.Ns[:4]
		ClearDNSSECInPlace(m)
	}); allocs != 0 {
		t.Errorf("in-place filter allocated %v times, want none", allocs)
	}
}
