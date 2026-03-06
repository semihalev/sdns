package cache

import (
	"testing"

	"github.com/miekg/dns"
)

// FuzzKey fuzzes the cache key generation function
func FuzzKey(f *testing.F) {
	// Add seed corpus with various domain names
	f.Add("example.com.", dns.TypeA, uint16(dns.ClassINET), false)
	f.Add("EXAMPLE.COM.", dns.TypeA, uint16(dns.ClassINET), false)
	f.Add("test.example.com.", dns.TypeAAAA, uint16(dns.ClassINET), true)
	f.Add(".", dns.TypeNS, uint16(dns.ClassINET), false)
	f.Add("", dns.TypeA, uint16(dns.ClassINET), false)
	f.Add("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.example.com.", dns.TypeMX, uint16(dns.ClassINET), false)

	f.Fuzz(func(t *testing.T, name string, qtype, qclass uint16, cd bool) {
		q := dns.Question{
			Name:   name,
			Qtype:  qtype,
			Qclass: qclass,
		}

		// This should not panic regardless of input
		_ = Key(q, cd)
	})
}

// FuzzKeyString fuzzes the string-based cache key function
func FuzzKeyString(f *testing.F) {
	// Add seed corpus
	f.Add("example.com.", dns.TypeA, uint16(dns.ClassINET), false)
	f.Add("EXAMPLE.COM.", dns.TypeA, uint16(dns.ClassINET), false)
	f.Add("", dns.TypeA, uint16(dns.ClassINET), false)
	f.Add("very-long-subdomain.another-subdomain.yet-another.example.com.", dns.TypeA, uint16(dns.ClassINET), true)

	f.Fuzz(func(t *testing.T, name string, qtype, qclass uint16, cd bool) {
		// This should not panic regardless of input
		_ = KeyString(name, qtype, qclass, cd)
	})
}

// FuzzKeyConsistency verifies that Key and KeyString produce consistent results
func FuzzKeyConsistency(f *testing.F) {
	f.Add("example.com.", dns.TypeA, uint16(dns.ClassINET), false)
	f.Add("TEST.EXAMPLE.COM.", dns.TypeAAAA, uint16(dns.ClassINET), true)

	f.Fuzz(func(t *testing.T, name string, qtype, qclass uint16, cd bool) {
		q := dns.Question{
			Name:   name,
			Qtype:  qtype,
			Qclass: qclass,
		}

		key1 := Key(q, cd)
		key2 := KeyString(name, qtype, qclass, cd)

		if key1 != key2 {
			t.Errorf("Key and KeyString produced different results for %q: %d vs %d", name, key1, key2)
		}
	})
}
