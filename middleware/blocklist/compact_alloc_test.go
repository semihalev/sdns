//go:build !race

package blocklist

import "testing"

func TestCompactWireLookupAlloc(t *testing.T) {
	checkCompactWireLookup(t, func(b *BlockList, wire []byte) {
		if n := testing.AllocsPerRun(100, func() { b.existsWire(wire) }); n != 0 {
			t.Fatalf("wire %x: allocs=%v", wire, n)
		}
	})
}
