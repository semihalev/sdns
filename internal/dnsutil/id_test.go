package dnsutil

import (
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// TestIDAllocatesNothing pins the point of the override: the default
// generator paid one heap allocation per call inside binary.Read.
func TestIDAllocatesNothing(t *testing.T) {
	if n := testing.AllocsPerRun(1000, func() { _ = dns.Id() }); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}

// TestIDSpread sanity-checks the distribution: 4096 draws from a healthy
// 16-bit generator collide only a little (expected distinct ≈ 3966).
func TestIDSpread(t *testing.T) {
	seen := make(map[uint16]struct{}, 4096)
	for range 4096 {
		seen[dns.Id()] = struct{}{}
	}
	if len(seen) < 3800 {
		t.Fatalf("distinct IDs = %d of 4096, generator looks degenerate", len(seen))
	}
}

// TestIDConcurrent exercises the generator from many goroutines under the
// race detector; the runtime source is per-M and must need no locking.
func TestIDConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10000 {
				_ = dns.Id()
			}
		}()
	}
	wg.Wait()
}
