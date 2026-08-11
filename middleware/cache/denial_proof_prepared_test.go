package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// denialProofNSECZone fills one zone with count NSEC intervals and returns a
// cache holding them plus a request that lands on an existing owner, so a
// lookup exercises the whole set the way a busy zone does: every entry is
// examined, one answers.
func denialProofNSECZone(tb testing.TB, count int) (*denialProofCache, *dns.Msg) {
	tb.Helper()

	now := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 4096, 2048, maxDenialProofTTL)

	// A single response may carry only so many records, so a zone reaches
	// this size the way it does in service: proof by proof.
	const perProof = 4
	for base := 0; base < count; base += perProof {
		intervals := make([][2]string, 0, perProof)
		for i := base; i < base+perProof; i++ {
			intervals = append(intervals, [2]string{
				fmt.Sprintf("a%03d.example.", i),
				fmt.Sprintf("a%03d.example.", i+1),
			})
		}
		fixture := newDenialProofNSECFixture(
			tb, now,
			fmt.Sprintf("a%03d.example.", base), dns.TypeAAAA,
			dns.RcodeSuccess, "example.", intervals...,
		)
		if !cache.record(fixture.msg, "example.", time.Time{}) {
			tb.Fatalf("validated NSEC proof at a%03d was not admitted", base)
		}
	}

	// An owner that exists but lacks AAAA: the fixture bitmap is
	// A/RRSIG/NSEC, so this resolves as NODATA off a single exact match
	// after the whole set has been examined.
	const qname = "a001.example."

	request := denialProofTestRequest(qname, dns.TypeAAAA, true)

	// Assert the verdict, not just that something came back: a mispaired
	// canonical name would still answer, only with the wrong denial — a
	// synthesized NXDOMAIN where the seeded proof says NODATA.
	response, ok := cache.Lookup(request, nil)
	if !ok {
		tb.Fatal("the seeded proof does not answer its own question")
	}
	if response.Rcode != dns.RcodeSuccess {
		tb.Fatalf("seeded NODATA answered as %s", dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 0 {
		tb.Fatalf("NODATA carries %d answers", len(response.Answer))
	}
	return cache, request
}

// TestDenialProofNSECLookupDoesNotRecanonicalize pins the reason the
// canonical form is stored on the entry: a lookup must not scale its
// allocation with the number of NSEC records in the zone. Before the
// prepared form existed, every lookup canonicalized both names of every
// record, so a zone with four times the records cost four times the
// allocation.
func TestDenialProofNSECLookupDoesNotRecanonicalize(t *testing.T) {
	smallCache, smallReq := denialProofNSECZone(t, 4)
	largeCache, largeReq := denialProofNSECZone(t, 32)

	small := testing.AllocsPerRun(50, func() {
		if _, ok := smallCache.Lookup(smallReq, nil); !ok {
			t.Fatal("lookup missed")
		}
	})
	large := testing.AllocsPerRun(50, func() {
		if _, ok := largeCache.Lookup(largeReq, nil); !ok {
			t.Fatal("lookup missed")
		}
	})

	// Eight times the records must not cost anywhere near eight times the
	// allocation; what remains scales with the entry slice, not with name
	// canonicalization.
	if large > small*2 {
		t.Fatalf("lookup allocations grew from %.0f (4 records) to %.0f (32 records); "+
			"the stored canonical form is not being used", small, large)
	}
	t.Logf("allocations per lookup: 4 records=%.0f, 32 records=%.0f", small, large)
}

func BenchmarkDenialProofNSECLookup(b *testing.B) {
	for _, count := range []int{4, 32} {
		b.Run(fmt.Sprintf("records=%d", count), func(b *testing.B) {
			cache, request := denialProofNSECZone(b, count)
			b.ReportAllocs()
			for b.Loop() {
				if _, ok := cache.Lookup(request, nil); !ok {
					b.Fatal("lookup missed")
				}
			}
		})
	}
}
