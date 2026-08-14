//go:build !race

package dnsname

import "testing"

// TestWalkersDoNotAllocate is the reason this package exists: every answer
// out of a forward walk, nothing materialized. CanonicalCompare's offset
// buffers must stay on the stack — an array pointer that escaped would put
// two kilobytes on the heap per comparison and quietly cancel the whole
// point.
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
