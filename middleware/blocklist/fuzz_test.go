package blocklist

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
)

// FuzzBlocklistExists fuzzes the blocklist existence check with wildcard support
func FuzzBlocklistExists(f *testing.F) {
	// Add seed corpus
	f.Add("example.com.")
	f.Add("sub.example.com.")
	f.Add("a.b.c.example.com.")
	f.Add("*.example.com.")
	f.Add("")
	f.Add(".")
	f.Add("EXAMPLE.COM.")
	f.Add("test-domain.co.uk.")
	f.Add("xn--nxasmq5b.com.") // IDN domain

	f.Fuzz(func(t *testing.T, domain string) {
		b := &BlockList{
			m:    make(map[string]bool),
			wild: make(map[string]bool),
			w:    make(map[string]bool),
		}

		// Add some test entries
		b.m["blocked.com."] = true
		b.m["test.example.com."] = true
		b.wild["example.org."] = true // Wildcard for *.example.org

		// This should not panic regardless of input
		_ = b.Exists(domain)
	})
}

// FuzzBlocklistSet fuzzes adding entries to the blocklist
func FuzzBlocklistSet(f *testing.F) {
	f.Add("example.com")
	f.Add("*.example.com")
	f.Add("sub.example.com")
	f.Add("")
	f.Add(".")
	f.Add("EXAMPLE.COM")
	f.Add("very.long.subdomain.chain.example.com")

	f.Fuzz(func(t *testing.T, domain string) {
		b := &BlockList{
			m:    make(map[string]bool),
			wild: make(map[string]bool),
			w:    make(map[string]bool),
		}

		// This should not panic regardless of input
		_ = b.set(domain)
	})
}

// FuzzBlocklistExistsWithWildcard fuzzes wildcard matching logic
func FuzzBlocklistExistsWithWildcard(f *testing.F) {
	f.Add("sub.example.com.", "example.com.")
	f.Add("a.b.c.test.org.", "test.org.")
	f.Add("", "")
	f.Add("exact.match.com.", "exact.match.com.")
	f.Add("no.match.com.", "different.org.")

	f.Fuzz(func(t *testing.T, domain, wildcardSuffix string) {
		b := &BlockList{
			m:    make(map[string]bool),
			wild: make(map[string]bool),
			w:    make(map[string]bool),
		}

		// Add wildcard entry
		if wildcardSuffix != "" {
			b.wild[wildcardSuffix] = true
		}

		// This should not panic regardless of input
		_ = b.Exists(domain)
	})
}

// FuzzCanonicalName fuzzes DNS canonical name conversion
func FuzzCanonicalName(f *testing.F) {
	f.Add("Example.COM")
	f.Add("TEST.example.com.")
	f.Add("")
	f.Add(".")
	f.Add("a.b.c.d.e.f.g.h.i.j.k")
	f.Add("xn--nxasmq5b.com")

	f.Fuzz(func(t *testing.T, name string) {
		// This should not panic regardless of input
		_ = dns.CanonicalName(name)
	})
}

// FuzzExistsWireMatchesExists fuzzes the wire lookup against Exists: for
// any wire-form name the key can be built from, both give one verdict.
func FuzzExistsWireMatchesExists(f *testing.F) {
	f.Add([]byte("\x07blocked\x04test\x00"))
	f.Add([]byte("\x03a.b\x07example\x00"))
	f.Add([]byte("\x04safe\x06parent\x04test\x00"))
	f.Add([]byte("\x01x\x04wild\x04test\x00"))
	f.Add([]byte("\x00"))
	f.Add([]byte("\x02\x01\xff\x07BLOCKED\x04TEST\x00"))

	b := &BlockList{
		m:    map[string]bool{"blocked.test.": true, `a\.b.example.`: true, "parent.test.": true},
		wild: map[string]bool{"wild.test.": true},
		w:    map[string]bool{"safe.parent.test.": true},
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		blocked, ok := b.existsWire(wire)
		if !ok {
			return
		}
		pres, ok := dnsname.AppendPresentation(nil, wire)
		if !ok {
			t.Fatalf("%x: key built but no presentation", wire)
		}
		if want := b.Exists(string(pres)); blocked != want {
			t.Fatalf("%s: wire lookup says %v, Exists says %v", pres, blocked, want)
		}
	})
}
