package dnsname

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func packName(t *testing.T, name string) []byte {
	t.Helper()
	buf := make([]byte, 512)
	off, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		t.Fatalf("pack %q: %v", name, err)
	}
	return buf[:off]
}

// TestAppendPresentationParity: byte-identical to dns.UnpackDomainName on
// every name both accept — including every possible label byte.
func TestAppendPresentationParity(t *testing.T) {
	names := []string{
		".",
		"example.com.",
		"WWW.Example.COM.",
		"a.b.c.d.e.f.g.h.",
		`ex\.ample.com.`,
		`sp\ ace.com.`,
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".com.",
	}
	for _, name := range names {
		wire := packName(t, name)
		want, end, err := dns.UnpackDomainName(wire, 0)
		if err != nil || end != len(wire) {
			t.Fatalf("%q: unpack err=%v end=%d len=%d", name, err, end, len(wire))
		}
		got, ok := AppendPresentation(nil, wire)
		if !ok {
			t.Fatalf("%q: walker refused a name the library accepts", name)
		}
		if string(got) != want {
			t.Fatalf("%q: got %q want %q", name, got, want)
		}
	}

	// Exhaustive single-byte labels.
	for c := 0; c < 256; c++ {
		wire := []byte{1, byte(c), 0}
		want, _, err := dns.UnpackDomainName(wire, 0)
		if err != nil {
			continue
		}
		got, ok := AppendPresentation(nil, wire)
		if !ok || string(got) != want {
			t.Fatalf("byte %d: got %q (ok=%v) want %q", c, got, ok, want)
		}
	}
}

// TestAppendFoldedKey matches the lookup-key spelling both hostsfile and
// domain metrics derive from the decoded presentation form.
func TestAppendFoldedKey(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"Probe.Test.", "probe.test"},
		{"WWW.EXAMPLE.COM.", "www.example.com"},
		{"already.lower.", "already.lower"},
		{".", ""},
		{`Sp\ ACE.com.`, `sp\ ace.com`},
	} {
		wire := packName(t, tc.name)
		got, ok := AppendFoldedKey(nil, wire)
		if !ok {
			t.Fatalf("%q refused", tc.name)
		}
		// The reference derivation: unpack, strip the trailing dot, fold.
		want, _, err := dns.UnpackDomainName(wire, 0)
		if err != nil {
			t.Fatal(err)
		}
		want = strings.ToLower(strings.TrimSuffix(want, "."))
		if want != tc.want {
			t.Fatalf("%q: reference derivation %q, expected %q", tc.name, want, tc.want)
		}
		if string(got) != want {
			t.Fatalf("%q: got %q want %q", tc.name, got, want)
		}
	}
}

func TestAppendWireNameRefusals(t *testing.T) {
	long := make([]byte, 256)
	for _, wire := range [][]byte{
		nil,
		{},
		{1, 'a'},            // truncated: no root byte
		{0xC0, 0x02},        // compression pointer
		{0x40, 'a', 0},      // reserved label type
		{1, 'a', 0, 1, 'b'}, // trailing bytes after root
		long,                // over the wire-form bound
		{63, 'a'},           // label runs past the buffer
	} {
		if _, ok := AppendPresentation(nil, wire); ok {
			t.Fatalf("accepted malformed wire %v", wire)
		}
		if _, ok := WireLabelCount(wire); ok {
			t.Fatalf("label count accepted malformed wire %v", wire)
		}
	}
}

func TestWireLabelCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{".", 0},
		{"com.", 1},
		{"example.com.", 2},
		{"a.b.c.d.e.", 5},
	} {
		wire := packName(t, tc.name)
		got, ok := WireLabelCount(wire)
		if !ok || got != tc.want {
			t.Fatalf("%q: got %d (ok=%v) want %d", tc.name, got, ok, tc.want)
		}
	}
}

// TestWireWalkersAllocateNothing pins the zero-allocation contract with a
// stack destination.
func TestWireWalkersAllocateNothing(t *testing.T) {
	wire := packName(t, "WWW.Example.COM.")
	if n := testing.AllocsPerRun(100, func() {
		var buf [MaxPresentationLength]byte
		if _, ok := AppendFoldedKey(buf[:0], wire); !ok {
			t.Fatal("refused")
		}
		if _, ok := AppendPresentation(buf[:0], wire); !ok {
			t.Fatal("refused")
		}
		if _, ok := WireLabelCount(wire); !ok {
			t.Fatal("refused")
		}
	}); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}
