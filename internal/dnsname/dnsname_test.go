package dnsname

import (
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// nameCorpus is every shape the walkers have to agree on: ordinary names,
// case differences, rooted and unrooted spellings, escapes in every position
// the scanner could misread, and the degenerate strings the library defines
// behavior for.
var nameCorpus = []string{
	".", "", "com.", "com", "example.com.", "example.com",
	"www.example.com.", "WWW.EXAMPLE.COM.", "wWw.eXaMpLe.CoM.",
	"a.b.c.d.e.f.example.com.", "*.example.com.",
	`foo\.bar.example.com.`, `foo\\.example.com.`, `foo\\\.bar.example.com.`,
	`\..`, `\\.`, `a\.`, `a\\.`, `end\.`,
	"xn--nme-qla.example.", "_dmarc.example.com.",
	"a.example.com.", "z.example.com.", "example.net.",
	"miek.nl.", "www.miek.nl.", "www.bla.nl.", "nl.", "nl",
	"very-long-label-that-goes-on-and-on-and-on-and-on-and-on-and-onx.example.",
	"1.2.0.192.in-addr.arpa.",
}

// TestCompareSuffixMatchesLibrary is the contract: dns.CompareDomainName's
// answer for every pair in the corpus.
func TestCompareSuffixMatchesLibrary(t *testing.T) {
	for _, a := range nameCorpus {
		for _, b := range nameCorpus {
			if got, want := CompareSuffix(a, b), dns.CompareDomainName(a, b); got != want {
				t.Errorf("CompareSuffix(%q, %q) = %d, library says %d",
					a, b, got, want)
			}
		}
	}
}

// TestSubMatchesLibrary pins dns.IsSubDomain parity over the same pairs.
func TestSubMatchesLibrary(t *testing.T) {
	for _, zone := range nameCorpus {
		for _, name := range nameCorpus {
			if got, want := Sub(zone, name), dns.IsSubDomain(zone, name); got != want {
				t.Errorf("Sub(%q, %q) = %v, library says %v",
					zone, name, got, want)
			}
		}
	}
}

// TestSuffixesMatchesLibrary pins dns.Split parity: the same offsets, in the
// same order, including the degenerate strings.
func TestSuffixesMatchesLibrary(t *testing.T) {
	for _, name := range nameCorpus {
		var got []int
		for off := range Suffixes(name) {
			got = append(got, off)
		}
		want := dns.Split(name)
		if !slices.Equal(got, want) {
			t.Errorf("Suffixes(%q) = %v, library says %v", name, got, want)
		}
	}
}

// canonicalReference is the implementation CanonicalCompare replaces, with
// one deliberate change: the ASCII fold this package uses instead of
// strings.ToLower, whose non-ASCII case mappings have no business in DNS
// names. For the ASCII corpus the two are the same function.
func canonicalReference(a, b string) int {
	al := dns.SplitDomainName(dns.Fqdn(a))
	bl := dns.SplitDomainName(dns.Fqdn(b))
	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		if c := strings.Compare(asciiLower(al[i]), asciiLower(bl[j])); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case len(al) < len(bl):
		return -1
	case len(al) > len(bl):
		return 1
	}
	return 0
}

// mixesHighBytesAndBackslash marks the input space where the library's
// IsFqdn rune bug can fire. Wider than the exact trigger on purpose: the
// oracle cedes only inputs no packed message can present.
func mixesHighBytesAndBackslash(s string) bool {
	high, backslash := false, false
	for i := range len(s) {
		switch {
		case s[i] >= 0x80:
			high = true
		case s[i] == '\\':
			backslash = true
		}
	}
	return high && backslash
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] |= 'a' - 'A'
		}
	}
	return string(b)
}

// TestCanonicalCompareMatchesReference pins the RFC 4034 §6.1 ordering
// against the reference for every pair, and the ordering laws on top: the
// relation must be antisymmetric and rooted/unrooted spellings must compare
// equal, or NSEC coverage proofs built on it would flicker with the
// spelling.
func TestCanonicalCompareMatchesReference(t *testing.T) {
	for _, a := range nameCorpus {
		for _, b := range nameCorpus {
			got := CanonicalCompare(a, b)
			if want := canonicalReference(a, b); got != want {
				t.Errorf("CanonicalCompare(%q, %q) = %d, reference says %d",
					a, b, got, want)
			}
			if back := CanonicalCompare(b, a); back != -got {
				t.Errorf("CanonicalCompare(%q, %q) = %d but reversed = %d",
					a, b, got, back)
			}
		}
	}

	for _, name := range nameCorpus {
		if name == "" || name == "." || dns.IsFqdn(name) {
			continue
		}
		if CanonicalCompare(name, dns.Fqdn(name)) != 0 {
			t.Errorf("%q does not compare equal to its rooted spelling", name)
		}
	}

	// The disagreement plain string order gets wrong, pinned by name.
	if CanonicalCompare("example.com.", "a.example.com.") != -1 {
		t.Error("the parent must sort before its child")
	}
	if CanonicalCompare("z.example.com.", "a.example.com.") != 1 {
		t.Error("right-to-left label order was not applied")
	}
}

// TestCanonicalCompareBeyondWireLabels pins the slow path: names with more
// labels than wire format allows still order correctly, against the same
// reference.
func TestCanonicalCompareBeyondWireLabels(t *testing.T) {
	long := strings.Repeat("a.", maxWireLabels+3) + "example.com."
	longer := "z." + long
	for _, pair := range [][2]string{
		{long, long},
		{long, longer},
		{long, "example.com."},
		{longer, "b." + long},
	} {
		if got, want := CanonicalCompare(pair[0], pair[1]),
			canonicalReference(pair[0], pair[1]); got != want {
			t.Errorf("beyond-wire pair: got %d, reference says %d", got, want)
		}
	}
}

// FuzzLabelWalkers drives all four walkers against their library oracles
// over arbitrary strings. The escape and boundary handling lives in the
// library's NextLabel either way, but the walks around it — alignment,
// streak counting, final-label slicing — are this package's own, and a
// hand-written corpus finds only the mistakes someone imagined.
func FuzzLabelWalkers(f *testing.F) {
	for _, name := range nameCorpus {
		f.Add(name, "example.com.")
	}
	f.Add(`a\`, `a\`)
	f.Add(`\\\\\.`, `\.`)

	f.Fuzz(func(t *testing.T, a, b string) {
		if got, want := CompareSuffix(a, b), dns.CompareDomainName(a, b); got != want {
			t.Fatalf("CompareSuffix(%q, %q) = %d, library says %d", a, b, got, want)
		}
		if got, want := Sub(a, b), dns.IsSubDomain(a, b); got != want {
			t.Fatalf("Sub(%q, %q) = %v, library says %v", a, b, got, want)
		}
		var got []int
		for off := range Suffixes(a) {
			got = append(got, off)
		}
		if want := dns.Split(a); !slices.Equal(got, want) {
			t.Fatalf("Suffixes(%q) = %v, library says %v", a, got, want)
		}

		// The canonical reference goes through Fqdn, whose IsFqdn miscounts
		// backslashes behind a raw multi-byte rune — a rune-versus-byte bug
		// this package deliberately does not inherit, documented on
		// CanonicalCompare. Presentation names are ASCII, so parity is
		// asserted wherever the shape that trips it cannot occur; on the
		// shapes that do, the ordering laws still have to hold.
		if mixesHighBytesAndBackslash(a) || mixesHighBytesAndBackslash(b) {
			if got, back := CanonicalCompare(a, b), CanonicalCompare(b, a); back != -got {
				t.Fatalf("CanonicalCompare(%q, %q) = %d but reversed = %d",
					a, b, got, back)
			}
			return
		}
		if got, want := CanonicalCompare(a, b), canonicalReference(a, b); got != want {
			t.Fatalf("CanonicalCompare(%q, %q) = %d, reference says %d",
				a, b, got, want)
		}
	})
}

func BenchmarkCompareSuffix(b *testing.B) {
	b.Run("owned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if CompareSuffix("www.miek.nl.", "miek.nl.") != 2 {
				b.Fatal("wrong answer")
			}
		}
	})
	b.Run("library", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if dns.CompareDomainName("www.miek.nl.", "miek.nl.") != 2 {
				b.Fatal("wrong answer")
			}
		}
	})
}

func BenchmarkSuffixes(b *testing.B) {
	b.Run("owned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			n := 0
			for range Suffixes("a.b.c.d.example.com.") {
				n++
			}
			if n != 6 {
				b.Fatal("wrong count")
			}
		}
	})
	b.Run("library", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if len(dns.Split("a.b.c.d.example.com.")) != 6 {
				b.Fatal("wrong count")
			}
		}
	})
}

func BenchmarkCanonicalCompare(b *testing.B) {
	b.Run("owned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if CanonicalCompare("b.example.com.", "Z.EXAMPLE.COM.") != -1 {
				b.Fatal("wrong order")
			}
		}
	})
	b.Run("reference", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if canonicalReference("b.example.com.", "Z.EXAMPLE.COM.") != -1 {
				b.Fatal("wrong order")
			}
		}
	})
}
