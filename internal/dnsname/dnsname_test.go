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

// canonicalWireReference is the independent oracle: the name packed to wire
// by the library — which is the authoritative decoder of presentation
// escapes — and RFC 4034 §6.3 applied to the resulting label octets. The
// comparator must agree with this, not with the implementation it replaced,
// whose ordering of escape text is the bug being fixed. ok=false marks a
// pair the packer refuses, where wire order is undefined.
func canonicalWireReference(a, b string) (int, bool) {
	// A name ending in a dangling backslash has no defined wire form, and
	// the library does not refuse it — Fqdn's appended root dot lands
	// behind the backslash and PackDomainName then collapses the whole
	// name to the root, silently. The oracle only binds where the wire
	// form is real; on these shapes the ordering laws still hold and are
	// asserted separately.
	if escapedTail(a, len(a)) || escapedTail(b, len(b)) {
		return 0, false
	}
	// Nor does it bind where the library disagrees with itself about the
	// rooting: IsFqdn counts trailing backslashes with rune arithmetic on a
	// byte question, so a multi-byte rune before the run flips its answer,
	// Fqdn roots (or fails to root) accordingly, and the packed form no
	// longer corresponds to the name. Both fuzz-found shapes of this are
	// pinned in the corpus.
	if fqdnDisagrees(a) || fqdnDisagrees(b) {
		return 0, false
	}
	la, okA := wireLabels(a)
	lb, okB := wireLabels(b)
	if !okA || !okB {
		return 0, false
	}
	i, j := len(la)-1, len(lb)-1
	for i >= 0 && j >= 0 {
		if c := strings.Compare(asciiLowerBytes(la[i]), asciiLowerBytes(lb[j])); c != 0 {
			return c, true
		}
		i--
		j--
	}
	switch {
	case len(la) < len(lb):
		return -1, true
	case len(la) > len(lb):
		return 1, true
	}
	return 0, true
}

// fqdnDisagrees reports the shapes where the library's IsFqdn — rune
// arithmetic on a byte question — answers differently from a byte count of
// the trailing backslashes.
func fqdnDisagrees(s string) bool {
	byteFqdn := len(s) > 0 && s[len(s)-1] == '.' && !escapedTail(s, len(s)-1)
	return dns.IsFqdn(s) != byteFqdn
}

func wireLabels(name string) ([][]byte, bool) {
	buf := make([]byte, 1024)
	n, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return nil, false
	}
	wire := buf[:n]
	var labels [][]byte
	for off := 0; off < len(wire); {
		l := int(wire[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(wire) {
			return nil, false
		}
		labels = append(labels, wire[off:off+l])
		off += l
	}
	return labels, true
}

func asciiLowerBytes(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c |= 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// TestCanonicalCompareMatchesWireOrder pins the RFC 4034 §6.3 ordering
// against the wire oracle for every packable pair, antisymmetry for every
// pair packable or not, and rooted/unrooted equivalence — an ordering NSEC
// coverage proofs stand on must not flicker with the spelling.
func TestCanonicalCompareMatchesWireOrder(t *testing.T) {
	for _, a := range nameCorpus {
		for _, b := range nameCorpus {
			got := CanonicalCompare(a, b)
			if want, ok := canonicalWireReference(a, b); ok && got != want {
				t.Errorf("CanonicalCompare(%q, %q) = %d, wire order says %d",
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

// TestCanonicalCompareDecodesEscapes pins the defect this ordering exists to
// fix, in the three shapes review demonstrated it with: presentation text is
// an encoding, and the order belongs to the octets behind it. The old
// comparator — and the first version of this one, which mirrored it —
// ordered the escape text, inverting names around `\` (0x5C) and splitting
// wire-equal spellings apart.
func TestCanonicalCompareDecodesEscapes(t *testing.T) {
	// `\046` is the octet 0x2E, which sorts before `0` (0x30); the escape
	// text starts with `\` (0x5C), which sorts after it.
	if got := CanonicalCompare(`\046.example.`, "0.example."); got != -1 {
		t.Errorf(`\046 vs 0: got %d, want -1 (0x2E < 0x30)`, got)
	}
	// `\065` is the octet 0x41 — the label `a` after the fold.
	if got := CanonicalCompare(`\065.example.`, "a.example."); got != 0 {
		t.Errorf(`\065 vs a: got %d, want 0`, got)
	}
	// One label, spelled two ways: an escaped dot and its decimal escape.
	if got := CanonicalCompare(`a\.b`, `a\046b`); got != 0 {
		t.Errorf(`a\.b vs a\046b: got %d, want 0`, got)
	}
	// And each agrees with the wire oracle, so the pins cannot drift from
	// the reference.
	for _, pair := range [][2]string{
		{`\046.example.`, "0.example."},
		{`\065.example.`, "a.example."},
		{`a\.b`, `a\046b`},
	} {
		want, ok := canonicalWireReference(pair[0], pair[1])
		if !ok {
			t.Fatalf("oracle refused %q vs %q", pair[0], pair[1])
		}
		if got := CanonicalCompare(pair[0], pair[1]); got != want {
			t.Errorf("%q vs %q: got %d, wire order says %d",
				pair[0], pair[1], got, want)
		}
	}
}

// TestCanonicalCompareManyLabels pins that the walk has no label-count
// ceiling: a name past wire limits still orders by the same rules, and the
// relation stays antisymmetric.
func TestCanonicalCompareManyLabels(t *testing.T) {
	long := strings.Repeat("a.", 150) + "example.com."
	longer := "z." + long
	if CanonicalCompare(long, longer) != -1 {
		t.Error("the shorter suffix must sort first")
	}
	if CanonicalCompare(longer, long) != 1 {
		t.Error("antisymmetry lost on long names")
	}
	if CanonicalCompare(long, long) != 0 {
		t.Error("a long name does not equal itself")
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

		// Canonical order is defined on wire octets, so the oracle is the
		// packed name; a string the packer refuses has no wire order, and
		// there only the ordering laws bind.
		order := CanonicalCompare(a, b)
		if back := CanonicalCompare(b, a); back != -order {
			t.Fatalf("CanonicalCompare(%q, %q) = %d but reversed = %d",
				a, b, order, back)
		}
		if want, ok := canonicalWireReference(a, b); ok && order != want {
			t.Fatalf("CanonicalCompare(%q, %q) = %d, wire order says %d",
				a, b, order, want)
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
	b.Run("previous", func(b *testing.B) {
		// The implementation this replaced: lower, root and split both
		// names, then compare label text.
		previous := func(a, c string) int {
			al := dns.SplitDomainName(strings.ToLower(dns.Fqdn(a)))
			bl := dns.SplitDomainName(strings.ToLower(dns.Fqdn(c)))
			i, j := len(al)-1, len(bl)-1
			for i >= 0 && j >= 0 {
				if r := strings.Compare(al[i], bl[j]); r != 0 {
					return r
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
		b.ReportAllocs()
		for b.Loop() {
			if previous("b.example.com.", "Z.EXAMPLE.COM.") != -1 {
				b.Fatal("wrong order")
			}
		}
	})
}
