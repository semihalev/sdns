package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

// TestClearDNSSECStripsTheAdditionalSection pins ClearDNSSEC on the section it
// used to leave alone: a DO=0 response carries no authenticating record it
// was not asked for (RFC 4035 §3.2.1), the additional section included, and
// the records those signatures covered stay. An explicit RRSIG question is
// still returned untouched.
func TestClearDNSSECStripsTheAdditionalSection(t *testing.T) {
	rrsig := func(owner string, covered uint16) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: covered, SignerName: "example.",
		}
	}
	build := func(qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("mx.example.", qtype)
		m.Answer = []dns.RR{
			&dns.MX{Hdr: dns.RR_Header{Name: "mx.example.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "target.example."},
			rrsig("mx.example.", dns.TypeMX),
		}
		m.Extra = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "target.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}},
			rrsig("target.example.", dns.TypeA),
			&dns.NSEC{Hdr: dns.RR_Header{Name: "target.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "z.example."},
		}
		return m
	}

	m := ClearDNSSEC(build(dns.TypeMX))
	for _, rr := range append(append([]dns.RR{}, m.Answer...), m.Extra...) {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3:
			t.Errorf("%s survived ClearDNSSEC", rr.Header().String())
		}
	}
	if len(m.Extra) != 1 {
		t.Fatalf("additional section holds %d records, want the address alone", len(m.Extra))
	}

	whole := ClearDNSSEC(build(dns.TypeRRSIG))
	if len(whole.Answer) != 2 || len(whole.Extra) != 3 {
		t.Fatal("an explicit RRSIG question was not returned untouched")
	}
}
