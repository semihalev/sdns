package edns

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// overflowTestMessage builds a compressible response of roughly size bytes:
// every record shares an owner suffix, so the compressed form is materially
// shorter than the uncompressed one.
func overflowTestMessage(tb testing.TB, records int) *dns.Msg {
	tb.Helper()
	m := new(dns.Msg)
	m.SetQuestion("very.long.owner.name.for.compression.example.com.", dns.TypeA)
	m.Compress = true
	for i := range records {
		rr, err := dns.NewRR(fmt.Sprintf(
			"host%03d.very.long.owner.name.for.compression.example.com. 300 IN A 192.0.2.%d",
			i, i%256,
		))
		if err != nil {
			tb.Fatalf("NewRR: %v", err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

// TestUDPOverflowMatchesExactLength is the contract the cheap bound has to
// keep: the answer must be the one Msg.Len would have given at every limit
// around the message's true size. A bound that ever under-estimates would
// let an oversize reply out on UDP without TC=1.
func TestUDPOverflowMatchesExactLength(t *testing.T) {
	for _, records := range []int{0, 1, 5, 40, 200} {
		m := overflowTestMessage(t, records)
		exact := m.Len()

		// An uncompressed message is never shorter, so the interesting
		// limits are the ones between the two lengths, where the cheap
		// bound is inconclusive and the exact length decides.
		uncompressed := *m
		uncompressed.Compress = false
		bound := uncompressed.Len()
		if bound < exact {
			t.Fatalf("records=%d: uncompressed length %d is below the compressed %d",
				records, bound, exact)
		}

		for _, limit := range []int{
			0, exact - 1, exact, exact + 1, bound - 1, bound, bound + 1, 4096,
		} {
			if limit < 0 {
				continue
			}
			if got, want := udpOverflow(m, limit), exact > limit; got != want {
				t.Fatalf("records=%d limit=%d: udpOverflow = %v, want %v (exact %d, bound %d)",
					records, limit, got, want, exact, bound)
			}
		}

		if !m.Compress {
			t.Fatalf("records=%d: the response was left uncompressed", records)
		}
	}
}

// TestUDPOverflowFitsWithoutAllocating pins the fast path. A response that
// clears the limit by its uncompressed length must not build a compression
// map, which is what every UDP reply used to pay for.
func TestUDPOverflowFitsWithoutAllocating(t *testing.T) {
	m := overflowTestMessage(t, 5)
	allocs := testing.AllocsPerRun(200, func() {
		if udpOverflow(m, 4096) {
			t.Fatal("a small response was reported as overflowing")
		}
	})
	if allocs != 0 {
		t.Fatalf("the fitting path allocated %.1f times per call, want 0", allocs)
	}
}

func BenchmarkUDPOverflow(b *testing.B) {
	m := overflowTestMessage(b, 20)
	b.ReportAllocs()
	for b.Loop() {
		if udpOverflow(m, 4096) {
			b.Fatal("unexpected overflow")
		}
	}
}

func BenchmarkUDPOverflowBySize(b *testing.B) {
	for _, records := range []int{1, 3, 10, 50} {
		m := overflowTestMessage(b, records)
		b.Run(fmt.Sprintf("records=%d", records), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if udpOverflow(m, 4096) {
					b.Fatal("unexpected overflow")
				}
			}
		})
	}
}
