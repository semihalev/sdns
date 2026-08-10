package cache

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestDenialProofNameOrderFallbackMatchesStringCompare pins the unpackable-
// name fallback the precomputed order inherited from the old per-comparison
// converter: when either side has no wire labels, ordering degrades to a
// plain comparison of the canonical presentation forms.
func TestDenialProofNameOrderFallbackMatchesStringCompare(t *testing.T) {
	overlongLabel := strings.Repeat("a", 64) + ".example.com."
	cases := []struct{ a, b string }{
		{overlongLabel, "b.example.com."},
		{"b.example.com.", overlongLabel},
		{overlongLabel, overlongLabel},
	}
	for _, tc := range cases {
		got := denialProofNameOrderFor(tc.a).compare(denialProofNameOrderFor(tc.b))
		want := strings.Compare(tc.a, tc.b)
		if (got < 0) != (want < 0) || (got == 0) != (want == 0) {
			t.Fatalf("compare(%q,%q) = %d, want sign of %d", tc.a, tc.b, got, want)
		}
	}
}

// BenchmarkDenialProofRecordChurn models the DNSBL-shaped admission stream
// that made snapshot republication the process's dominant allocation site: a
// zone shard already holding many NSEC entries receives a replacement
// admission, forcing a full snapshot re-sort. Before the precomputed
// ownerOrder, every comparison re-derived both names' wire labels.
func BenchmarkDenialProofRecordChurn(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	cache := newDenialProofTestCache(&now, 4096, 512, time.Hour)

	const zone = "bl.example."
	const preload = 200
	for i := range preload {
		owner := fmt.Sprintf("h%03d.%s", i, zone)
		next := fmt.Sprintf("h%03dz.%s", i, zone)
		fixture := newDenialProofNSECFixture(
			b,
			now,
			fmt.Sprintf("q%03d.%s", i, zone),
			dns.TypeA,
			dns.RcodeNameError,
			zone,
			[2]string{owner, next},
		)
		if !cache.record(fixture.msg, zone, time.Time{}) {
			b.Fatalf("preload admission %d rejected", i)
		}
	}
	if got := cache.len(); got != preload+1 { // + shared SOA entry
		b.Fatalf("preloaded entries = %d, want %d", got, preload+1)
	}

	churn := newDenialProofNSECFixture(
		b,
		now,
		"qchurn."+zone,
		dns.TypeA,
		dns.RcodeNameError,
		zone,
		[2]string{"h000." + zone, "h000z." + zone},
	)

	b.ReportAllocs()
	for b.Loop() {
		if !cache.record(churn.msg, zone, time.Time{}) {
			b.Fatal("churn admission rejected")
		}
	}
}
