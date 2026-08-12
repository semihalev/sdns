package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestAggressiveCanonicalNameRejectsOverlongName pins the wire-format ceiling
// to the packing buffer. PackDomainName does not enforce the 255-octet limit
// itself, so a buffer sized purely from the presentation form would start
// admitting names no resolver may canonicalize.
func TestAggressiveCanonicalNameRejectsOverlongName(t *testing.T) {
	overlong := strings.Repeat(strings.Repeat("a", 63)+".", 5) + "com."
	if _, err := newAggressiveCanonicalName(overlong); err == nil {
		t.Fatalf("canonicalized a %d-octet name, want rejection", len(overlong))
	}

	// The longest name that still fits: 255 wire octets.
	fits := strings.Repeat(strings.Repeat("a", 49)+".", 5) + "com."
	packed := make([]byte, 512)
	wire, err := dns.PackDomainName(fits, packed, 0, nil, false)
	if err != nil || wire != 255 {
		t.Fatalf("fixture is %d wire octets (err %v), want exactly 255", wire, err)
	}
	if _, err := newAggressiveCanonicalName(fits); err != nil {
		t.Fatalf("rejected a 255-octet name: %v", err)
	}
}

// TestAggressiveCanonicalNameSizedBuffer covers the shapes where the buffer
// bound is tightest: escaped separators, which make the wire form shorter than
// the text, and the root. A buffer one octet short would fail to pack them.
func TestAggressiveCanonicalNameSizedBuffer(t *testing.T) {
	for _, name := range []string{
		".",
		"a.",
		"example.com",
		"example.com.",
		`a\.b.example.com.`,
		`\..`,
		strings.Repeat(`\.`, 30) + ".example.com.",
	} {
		canonical, err := newAggressiveCanonicalName(name)
		if err != nil {
			t.Fatalf("newAggressiveCanonicalName(%q): %v", name, err)
		}
		reference := make([]byte, 512)
		end, err := dns.PackDomainName(dns.Fqdn(name), reference, 0, nil, false)
		if err != nil {
			t.Fatalf("reference pack of %q: %v", name, err)
		}
		if got, want := string(canonical.wire), string(reference[:end]); got != want {
			t.Fatalf("wire form of %q = %q, want %q", name, got, want)
		}
	}
}

func BenchmarkAggressiveCanonicalName(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := newAggressiveCanonicalName("www.example.com."); err != nil {
			b.Fatal(err)
		}
	}
}
