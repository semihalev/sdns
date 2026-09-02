package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestHasNSEC3OptOutUsesDNSASCIICaseFolding(t *testing.T) {
	optOut := func(owner string, flags uint8) dns.RR {
		return &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
			},
			Flags: flags,
		}
	}

	if !HasNSEC3OptOut([]dns.RR{optOut("HASH.k.example.", 1)}, "K.Example.") {
		t.Fatal("in-zone NSEC3 Opt-Out record was not detected")
	}
	if HasNSEC3OptOut([]dns.RR{optOut("HASH.k.example.", 0)}, "k.example.") {
		t.Fatal("ordinary NSEC3 record was classified as Opt-Out")
	}
	if HasNSEC3OptOut([]dns.RR{optOut("HASH.\u212A.example.", 1)}, "k.example.") {
		t.Fatal("Unicode folding aliased Kelvin-sign and ASCII-k signer zones")
	}
}

func TestFilterRRsToZoneUsesDNSASCIICaseFolding(t *testing.T) {
	nsec := func(owner, next string) dns.RR {
		return &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
			},
			NextDomain: next,
		}
	}

	inZone := nsec("A.K.Example.", "Z.k.example.")
	kelvinOwner := nsec("a.\u212A.example.", "z.k.example.")
	kelvinNext := nsec("a.k.example.", "z.\u212A.example.")
	got := FilterRRsToZone(
		[]dns.RR{inZone, kelvinOwner, kelvinNext},
		"k.example.",
	)
	if len(got) != 1 || got[0] != inZone {
		t.Fatalf("filtered records = %v, want only ASCII-case-equivalent in-zone NSEC", got)
	}
}

// TestNameInZoneRequiresARealSeparator pins that zone containment is decided
// on labels, not on text.
//
// A dot written `\.` is part of a label, so `foo\.example.com.` is the two
// labels `foo.example` and `com`: it ends with the text of `example.com.`
// while living outside that zone entirely. Every DNSSEC containment check in
// the resolver comes through here, so reading it as a descendant would let a
// key authenticate an owner it has no authority over.
func TestNameInZoneRequiresARealSeparator(t *testing.T) {
	for _, tc := range []struct {
		name string
		zone string
		want bool
	}{
		{"example.com.", "example.com.", true},
		{"www.example.com.", "example.com.", true},
		{"a.b.example.com.", "example.com.", true},
		{"example.com.", ".", true},
		{"anything.", "", true},

		{"evilexample.com.", "example.com.", false},
		{"com.", "example.com.", false},
		{"example.org.", "example.com.", false},

		// The escaped separator: a literal dot inside a single label.
		{`foo\.example.com.`, "example.com.", false},
		{`a.foo\.example.com.`, "example.com.", false},
		{`foo\.example.com.`, "com.", true},
		{`foo\.example.com.`, `foo\.example.com.`, true},
		{`x.foo\.example.com.`, `foo\.example.com.`, true},

		// An escaped backslash is not an escaped dot: the separator after
		// it is a separator.
		{`foo\\.example.com.`, "example.com.", true},
		{`foo\\\.example.com.`, "example.com.", false},
	} {
		if got := NameInZone(tc.name, tc.zone); got != tc.want {
			t.Errorf("NameInZone(%q, %q) = %v, want %v",
				tc.name, tc.zone, got, tc.want)
		}
	}
}

// TestNameInZoneDoesNotAllocate keeps the check off the allocator. It runs
// for every RRset of every signed response, and the old form compared against
// a freshly built "."+zone, free on the stack for a short zone, a heap
// allocation per call once the zone name reached the runtime's 32-octet
// temporary buffer, which ordinary delegation names do.
func TestNameInZoneDoesNotAllocate(t *testing.T) {
	const longZone = "a-rather-long-delegation-name.under.some.deep.example.com."
	if len(longZone) < 32 {
		t.Fatal("fixture is wrong: the zone name is short enough to stay on the stack")
	}
	longName := "www." + longZone

	allocs := testing.AllocsPerRun(200, func() {
		if !NameInZone("www.example.com.", "example.com.") {
			t.Fatal("in-zone name rejected")
		}
		if NameInZone("evilexample.com.", "example.com.") {
			t.Fatal("out-of-zone name accepted")
		}
		if !NameInZone(longName, longZone) {
			t.Fatal("in-zone name under a long zone rejected")
		}
	})
	if allocs != 0 {
		t.Fatalf("NameInZone cost %.0f allocations", allocs)
	}
}
