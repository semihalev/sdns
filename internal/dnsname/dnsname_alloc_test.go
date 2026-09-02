//go:build !race

package dnsname

import "testing"

// TestWalkersDoNotAllocate is the reason this package exists: every answer
// out of a forward walk, nothing materialized, CanonicalCompare included,
// whose escape decoding happens octet by octet as the labels are read.
func TestWalkersDoNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(200, func() {
		if CompareSuffix("www.miek.nl.", "miek.nl.") != 2 {
			t.Fatal("wrong answer")
		}
		if !Sub("example.com.", "a.b.example.com.") {
			t.Fatal("wrong answer")
		}
		n := 0
		for range Suffixes("a.b.c.d.example.com.") {
			n++
		}
		if n != 6 {
			t.Fatal("wrong count")
		}
		if CanonicalCompare("b.example.com.", "Z.EXAMPLE.COM.") != -1 {
			t.Fatal("wrong order")
		}
		if CanonicalCompare(`foo\.bar.example.com.`, "foo.bar.example.com.") == 0 {
			t.Fatal("an escaped dot compared as a separator")
		}
	})
	if allocs != 0 {
		t.Fatalf("the walkers cost %.0f allocations", allocs)
	}
}
