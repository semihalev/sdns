package dnsutil

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestClassifyANYAndNotImplemented pins the two classifier facts behind the
// ANY policy. An ANY answer holds records of every type but never one of
// type 255, so it is answered by whatever it carries: a full answer that
// happened to include a SOA was read as a NODATA denial. And NOTIMP is a
// statement about the question, not a resolution failure: classified as
// one, it was recorded in the failure cache and the next identical question
// was answered SERVFAIL from there.
func TestClassifyANYAndNotImplemented(t *testing.T) {
	now := time.Now()
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns.example.", Mbox: "hostmaster.example.", Minttl: 300,
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}}
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "y.example."}

	for _, tc := range []struct {
		name   string
		answer []dns.RR
		ns     []dns.RR
		rcode  int
		want   ResponseType
	}{
		{"ANY answered with an address and a SOA beside it", []dns.RR{a, soa}, nil, dns.RcodeSuccess, TypeSuccess},
		{"ANY answered with the SOA in the authority section", []dns.RR{a}, []dns.RR{soa}, dns.RcodeSuccess, TypeSuccess},
		{"ANY answered by an alias alone", []dns.RR{cname}, nil, dns.RcodeSuccess, TypeSuccess},
		{"ANY with nothing in the answer and a SOA is a denial", nil, []dns.RR{soa}, dns.RcodeSuccess, TypeNoRecords},
		{"NOTIMP is not cacheable and not a failure", nil, nil, dns.RcodeNotImplemented, TypeNotCacheable},
		{"REFUSED stays a failure", nil, nil, dns.RcodeRefused, TypeServerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion("x.example.", dns.TypeANY)
			m.Rcode = tc.rcode
			m.Answer, m.Ns = tc.answer, tc.ns
			if got, _ := ClassifyResponse(m, now); got != tc.want {
				t.Fatalf("classified %v, want %v", got, tc.want)
			}
		})
	}
}
