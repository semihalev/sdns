package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

// BenchmarkNSECCovers exercises the canonical-order comparisons every NSEC
// coverage decision makes — three per candidate record, for every record of
// every aggressive-cache probe.
func BenchmarkNSECCovers(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if !nsecCovers("a.example.com.", "m.example.com.", "b.example.com.") {
			b.Fatal("coverage lost")
		}
		if nsecCovers("a.example.com.", "m.example.com.", "z.example.com.") {
			b.Fatal("false coverage")
		}
	}
}

// BenchmarkClosestEncloserFromNSEC exercises the shared-suffix walk and the
// encloser reconstruction.
func BenchmarkClosestEncloserFromNSEC(b *testing.B) {
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name: "alpha.example.com.", Rrtype: dns.TypeNSEC,
			Class: dns.ClassINET, Ttl: 300,
		},
		NextDomain: "delta.example.com.",
	}
	b.ReportAllocs()
	for b.Loop() {
		if closestEncloserFromNSEC("b.c.example.com.", nsec) != "example.com." {
			b.Fatal("wrong encloser")
		}
	}
}
