package cache

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// packName packs a presentation name to wire form, failing the test on
// names the library refuses.
func packName(tb testing.TB, name string) []byte {
	tb.Helper()
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		tb.Fatalf("PackDomainName(%q): %v", name, err)
	}
	return buf[:off]
}

// wireLabel builds one raw wire name from literal label byte strings,
// bytes the presentation form could only spell through escapes.
func wireLabels(labels ...[]byte) []byte {
	var out []byte
	for _, l := range labels {
		out = append(out, byte(len(l))) //nolint:gosec // fixture labels are ≤63 bytes
		out = append(out, l...)
	}
	return append(out, 0)
}

// TestKeyWireMatchesKeyOverPresentationNames pins the canonical-key
// contract from the presentation side: packing a name and hashing its wire
// form equals hashing the name string, for every escape class the
// presentation format has.
func TestKeyWireMatchesKeyOverPresentationNames(t *testing.T) {
	names := []string{
		".",
		"example.com.",
		"EXAMPLE.CoM.",
		"a.b.c.d.e.example.com.",
		`with\.dot.example.com.`,
		`with\\backslash.example.com.`,
		`with\032space.example.com.`,
		`quote\"and\'and\@and\;and\(and\).example.com.`,
		`ddd\000low.example.com.`,
		`ddd\031edge.example.com.`,
		`ddd\127del.example.com.`,
		`ddd\255high.example.com.`,
		`MiXeD\068case.example.com.`, // \068 is 'D': stays escaped in presentation, folds only literals
		"xn--bcher-kva.example.",
	}
	for _, name := range names {
		wire := packName(t, name)
		for _, cd := range []bool{false, true} {
			// The reference is what the Msg path computes for the decoded
			// form of these exact wire bytes.
			decoded, _, err := dns.UnpackDomainName(wire, 0)
			if err != nil {
				t.Fatalf("UnpackDomainName(%q): %v", name, err)
			}
			want := KeyString(decoded, dns.TypeA, dns.ClassINET, cd)
			got, ok := KeyWire(wire, dns.TypeA, dns.ClassINET, cd)
			if !ok {
				t.Fatalf("KeyWire refused packed %q", name)
			}
			if got != want {
				t.Fatalf("KeyWire(%q, cd=%v) = %x, Key over decoded %q = %x",
					name, cd, got, decoded, want)
			}
		}
	}
}

// TestKeyWireMatchesKeyOverRawLabelBytes drives the equivalence from the
// wire side: raw label octets across the whole byte range must hash as the
// library's decoded presentation of the same bytes.
func TestKeyWireMatchesKeyOverRawLabelBytes(t *testing.T) {
	cases := [][]byte{
		wireLabels([]byte{'.'}, []byte("example"), []byte("com")),
		wireLabels([]byte{'\\'}, []byte("example"), []byte("com")),
		wireLabels([]byte{' ', '\'', '@', ';', '(', ')', '"'}, []byte("com")),
		wireLabels([]byte{0x00, 0x1F, 0x7F, 0xFF}, []byte("com")),
		wireLabels([]byte("ALLUPPER"), []byte("COM")),
		wireLabels([]byte{'A', 0x00, 'z', '.', 0xC0}, []byte("mixed")),
	}
	// Every label byte value, one per name.
	for b := 0; b < 256; b++ {
		cases = append(cases, wireLabels([]byte{byte(b)}, []byte("x")))
	}

	for _, wire := range cases {
		decoded, off, err := dns.UnpackDomainName(wire, 0)
		if err != nil {
			t.Fatalf("UnpackDomainName(%x): %v", wire, err)
		}
		if off != len(wire) {
			t.Fatalf("reference did not consume the whole name: %x", wire)
		}
		want := KeyString(decoded, dns.TypeAAAA, dns.ClassINET, false)
		got, ok := KeyWire(wire, dns.TypeAAAA, dns.ClassINET, false)
		if !ok {
			t.Fatalf("KeyWire refused %x (decodes to %q)", wire, decoded)
		}
		if got != want {
			t.Fatalf("KeyWire(%x) = %x, want %x (decoded %q)", wire, got, want, decoded)
		}
	}
}

// TestKeyWireRandomDifferential fuzzes random label structures against the
// decode-then-hash reference.
func TestKeyWireRandomDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5D45)) //nolint:gosec // deterministic differential corpus, not crypto
	for i := 0; i < 5000; i++ {
		labelCount := 1 + rng.Intn(5)
		var labels [][]byte
		total := 0
		for l := 0; l < labelCount && total < 200; l++ {
			n := 1 + rng.Intn(20)
			label := make([]byte, n)
			for j := range label {
				label[j] = byte(rng.Intn(256)) //nolint:gosec // full byte range is the point
			}
			labels = append(labels, label)
			total += n + 1
		}
		wire := wireLabels(labels...)
		decoded, _, err := dns.UnpackDomainName(wire, 0)
		if err != nil {
			continue // the reference refuses; nothing to compare
		}
		cd := rng.Intn(2) == 1
		qtype := uint16(rng.Intn(0x10000)) //nolint:gosec // bounded
		want := KeyString(decoded, qtype, dns.ClassINET, cd)
		got, ok := KeyWire(wire, qtype, dns.ClassINET, cd)
		if !ok {
			t.Fatalf("KeyWire refused %x", wire)
		}
		if got != want {
			t.Fatalf("differential mismatch on %x (decoded %q)", wire, decoded)
		}
	}
}

// TestKeyWireWithPrefixMatchesKeyWithPrefix pins the ECS extension against
// the presentation-side reference, both families, byte-rounded and exact
// prefixes, plus the invalid-prefix collapse.
func TestKeyWireWithPrefixMatchesKeyWithPrefix(t *testing.T) {
	wire := packName(t, "scoped.example.com.")
	q := dns.Question{Name: "scoped.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("203.0.112.0/22"),
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("2001:db8::/56"),
		netip.MustParsePrefix("2001:db8:1234::1/128"),
		netip.MustParsePrefix("0.0.0.0/0"),
		{}, // invalid: collapses to the unscoped key
	}
	for _, prefix := range prefixes {
		for _, cd := range []bool{false, true} {
			want := KeyWithPrefix(q, cd, prefix)
			got, ok := KeyWireWithPrefix(wire, q.Qtype, q.Qclass, cd, prefix)
			if !ok {
				t.Fatalf("refused prefix %v", prefix)
			}
			if got != want {
				t.Fatalf("prefix %v cd=%v: wire %x != presentation %x", prefix, cd, got, want)
			}
		}
	}
}

// TestKeyWireRefusals pins the backstop: compressed, truncated, oversized,
// trailing-byte, and empty names refuse instead of hashing garbage.
func TestKeyWireRefusals(t *testing.T) {
	huge := make([]byte, 0, 300)
	for i := 0; i < 5; i++ {
		huge = append(huge, 63)
		for j := 0; j < 63; j++ {
			huge = append(huge, 'a')
		}
	}
	huge = append(huge, 0)

	cases := map[string][]byte{
		"empty":            {},
		"compression ptr":  {0xC0, 0x0C},
		"reserved label":   {0x40, 'a', 0},
		"truncated label":  {5, 'a', 'b'},
		"missing root":     {1, 'a'},
		"trailing garbage": {1, 'a', 0, 'x'},
		"oversized":        huge,
	}
	for name, wire := range cases {
		if _, ok := KeyWire(wire, dns.TypeA, dns.ClassINET, false); ok {
			t.Fatalf("%s: KeyWire accepted %x", name, wire)
		}
	}
}

// TestKeyWireAllocsNothing pins the streaming property for both variants.
func TestKeyWireAllocsNothing(t *testing.T) {
	wire := packName(t, "steady.zero.example.com.")
	prefix := netip.MustParsePrefix("2001:db8::/56")
	allocs := testing.AllocsPerRun(200, func() {
		if _, ok := KeyWire(wire, dns.TypeA, dns.ClassINET, false); !ok {
			t.Fatal("refused")
		}
		if _, ok := KeyWireWithPrefix(wire, dns.TypeA, dns.ClassINET, true, prefix); !ok {
			t.Fatal("refused")
		}
	})
	if allocs != 0 {
		t.Fatalf("wire key hashing allocated %.0f times per pair, want 0", allocs)
	}
}
