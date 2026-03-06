package blocklist

import (
	"testing"

	"github.com/miekg/dns"
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
