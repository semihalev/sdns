package cache

import (
	"testing"

	"github.com/miekg/dns"
)

// TestFilterCacheableAnswerShallow pins the copy discipline: a response
// with nothing to drop passes through as itself, and a response with a
// chain tail gets a shallow view, same records, same other sections,
// with only the Answer slice rebuilt and the original untouched.
func TestFilterCacheableAnswerShallow(t *testing.T) {
	mk := func(owner string, target string) dns.RR {
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: target,
		}
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "Example.COM.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "a.", Mbox: "."}

	res := new(dns.Msg)
	res.SetQuestion("example.com.", dns.TypeA)
	res.Answer = []dns.RR{a}
	res.Ns = []dns.RR{soa}

	// Case-insensitive owner match: nothing to drop, no copy at all.
	if got := filterCacheableAnswer(res); got != res {
		t.Fatal("clean answer must pass through as the same message")
	}

	// A chain tail with a foreign owner drops; the view is shallow.
	tail := mk("tail.example.net.", "x.")
	res.Answer = []dns.RR{a, tail}
	got := filterCacheableAnswer(res)
	if got == res {
		t.Fatal("a dropped record must produce a new view")
	}
	if len(got.Answer) != 1 || got.Answer[0] != dns.RR(a) {
		t.Fatalf("filtered answer = %v, want the qname record shared by pointer", got.Answer)
	}
	if len(res.Answer) != 2 {
		t.Fatal("the original message was mutated")
	}
	if &got.Ns[0] != &res.Ns[0] {
		t.Fatal("authority section must be shared, not copied")
	}
	if got.Id != res.Id || got.Question[0] != res.Question[0] {
		t.Fatal("header/question must carry over")
	}

	// DNAME and its covering RRSIG survive under a foreign owner.
	dname := &dns.DNAME{Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 60}, Target: "other.net."}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeDNAME}
	res.Answer = []dns.RR{dname, sig, tail}
	got = filterCacheableAnswer(res)
	if len(got.Answer) != 2 {
		t.Fatalf("DNAME+RRSIG must survive, tail must drop: %v", got.Answer)
	}

	// A foreign-owner RRSIG covering a non-DNAME type drops with its tail.
	tailSig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "tail.example.net.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeA}
	res.Answer = []dns.RR{a, tail, tailSig}
	if got = filterCacheableAnswer(res); len(got.Answer) != 1 {
		t.Fatalf("foreign RRSIG over non-DNAME must drop: %v", got.Answer)
	}

	// Everything dropping leaves an empty, but servable, answer section.
	res.Answer = []dns.RR{tail, tailSig}
	if got = filterCacheableAnswer(res); len(got.Answer) != 0 || got == res {
		t.Fatalf("all-dropped must yield an empty answer in a new view: %v", got.Answer)
	}
}
