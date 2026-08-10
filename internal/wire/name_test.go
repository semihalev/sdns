package wire

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func packName(t *testing.T, name string) []byte {
	t.Helper()
	var buf [255]byte
	n, err := dns.PackDomainName(name, buf[:], 0, nil, false)
	if err != nil {
		t.Fatalf("PackDomainName(%q): %v", name, err)
	}
	return bytes.Clone(buf[:n])
}

// escapeFreeNames are names whose presentation form is a plain transcription
// of their labels, the shape the shortcut is allowed to recognise.
var escapeFreeNames = []string{
	".",
	"com.",
	"example.com.",
	"www.example.com.",
	"WWW.Example.COM.",
	"wwW.example.com.",
	"a.example.com.",
	"example.co.",
	"example.com.tr.",
	"xn--nda.example.com.",
	"_dmarc.example.com.",
	strings.Repeat("a", 63) + ".example.com.",
	strings.Repeat("x.", 60) + "example.com.",
}

// TestNameEqualsPresentationMatchesWireEquality is the shortcut's whole
// contract, checked against the encoder it exists to skip: for every pair of
// escape-free names, claiming equality must agree exactly with the packed
// forms being identical. A false positive here would echo the stored
// question spelling back to a client that asked in a different case, so the
// cross-product is checked rather than a handful of chosen pairs.
func TestNameEqualsPresentationMatchesWireEquality(t *testing.T) {
	for _, stored := range escapeFreeNames {
		packed := packName(t, stored)
		for _, requested := range escapeFreeNames {
			want := bytes.Equal(packed, packName(t, requested))
			if got := NameEqualsPresentation(packed, requested); got != want {
				t.Errorf("NameEqualsPresentation(pack(%q), %q) = %v, want %v",
					stored, requested, got, want)
			}
		}
	}
}

// TestNameEqualsPresentationNeverFalsePositive covers the inputs the
// shortcut is required to decline rather than interpret: escapes, a
// compression pointer, a relative name, and truncated or trailing bytes.
// Declining is always safe — the caller re-encodes — so only a true answer
// can be wrong.
func TestNameEqualsPresentationNeverFalsePositive(t *testing.T) {
	tests := []struct {
		name   string
		packed []byte
		input  string
		want   bool
	}{
		{
			// "a.b" as a single label: the dot is data, not a separator, so
			// the presentation form carries an escape and must be declined
			// even though the bytes would otherwise line up.
			name:   "escaped dot in label",
			packed: packName(t, `a\.b.example.com.`),
			input:  `a\.b.example.com.`,
		},
		{
			name:   "escaped decimal",
			packed: packName(t, `\097.example.com.`),
			input:  `\097.example.com.`,
		},
		{
			// The same name written two ways: a shortcut that resolved
			// escapes could call these equal, which is correct but is not
			// what this helper promises. Declining keeps it honest.
			name:   "escaped decimal against its plain form",
			packed: packName(t, "a.example.com."),
			input:  `\097.example.com.`,
		},
		{
			name:   "compression pointer",
			packed: []byte{0xC0, 0x0C},
			input:  "example.com.",
		},
		{
			name:   "reserved label type",
			packed: []byte{0x80, 0x01, 0x00},
			input:  "example.com.",
		},
		{
			name:   "relative name",
			packed: packName(t, "example.com."),
			input:  "example.com",
		},
		{
			name:   "empty name",
			packed: packName(t, "example.com."),
			input:  "",
		},
		{
			name:   "empty packed",
			packed: nil,
			input:  "example.com.",
		},
		{
			name:   "root packed against a real name",
			packed: []byte{0x00},
			input:  "example.com.",
		},
		{
			name:   "root name against a real packed name",
			packed: packName(t, "example.com."),
			input:  ".",
		},
		{
			name:   "root",
			packed: []byte{0x00},
			input:  ".",
			want:   true,
		},
		{
			// Truncated mid-label: the length byte promises bytes the buffer
			// does not hold.
			name:   "label runs past the buffer",
			packed: []byte{0x07, 'e', 'x', 'a'},
			input:  "example.com.",
		},
		{
			// No terminating zero, so the name never completes.
			name:   "unterminated",
			packed: []byte{0x03, 'c', 'o', 'm'},
			input:  "com.",
		},
		{
			name:   "packed name is a prefix of the request",
			packed: packName(t, "com."),
			input:  "com.example.com.",
		},
		{
			name:   "request is a prefix of the packed name",
			packed: packName(t, "www.example.com."),
			input:  "www.",
		},
		{
			name:   "same labels, different boundaries",
			packed: packName(t, "ab.example.com."),
			input:  "a.bexample.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NameEqualsPresentation(tt.packed, tt.input); got != tt.want {
				t.Fatalf("NameEqualsPresentation(%v, %q) = %v, want %v",
					tt.packed, tt.input, got, tt.want)
			}
		})
	}
}

// TestNameEqualsPresentationAllocFree pins the shortcut's reason for
// existing: it must read the two forms in place, never building a third.
func TestNameEqualsPresentationAllocFree(t *testing.T) {
	packed := packName(t, "www.a-fairly-long-name.example.com.")
	const name = "www.a-fairly-long-name.example.com."
	if allocs := testing.AllocsPerRun(200, func() {
		if !NameEqualsPresentation(packed, name) {
			t.Fatal("expected a match")
		}
	}); allocs != 0 {
		t.Fatalf("NameEqualsPresentation allocated %.1f times per call", allocs)
	}
}

func BenchmarkNameEqualsPresentation(b *testing.B) {
	const name = "www.a-fairly-long-name.example.com."
	var buf [255]byte
	n, err := dns.PackDomainName(name, buf[:], 0, nil, false)
	if err != nil {
		b.Fatal(err)
	}
	packed := buf[:n]
	b.ReportAllocs()
	for b.Loop() {
		if !NameEqualsPresentation(packed, name) {
			b.Fatal("expected a match")
		}
	}
}

func BenchmarkPackDomainNameForComparison(b *testing.B) {
	const name = "www.a-fairly-long-name.example.com."
	b.ReportAllocs()
	for b.Loop() {
		var buf [255]byte
		if _, err := dns.PackDomainName(name, buf[:], 0, nil, false); err != nil {
			b.Fatal(err)
		}
	}
}
