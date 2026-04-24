package authcache

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_TrySort(t *testing.T) {
	s := &AuthServers{
		List: []*AuthServer{},
	}

	for i := 0; i < 10; i++ {
		s.List = append(s.List, NewAuthServer(fmt.Sprintf("0.0.0.%d:53", i), IPv4))
		s.List = append(s.List, NewAuthServer(fmt.Sprintf("[::%d]:53", i), IPv6))
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // G404 - test file, not used for crypto
	for i := 0; i < 2000; i++ {
		for j := range s.List {
			s.List[j].Count++
			s.List[j].Rtt += (time.Duration(r.Intn(2000-0)+0) * time.Millisecond).Nanoseconds()
			Sort(s.List, uint64(i))
		}
	}

	assert.Equal(t, int64(1), s.List[0].Count)
}

func Test_VersionString(t *testing.T) {
	assert.Equal(t, "IPv4", IPv4.String())
	assert.Equal(t, "IPv6", IPv6.String())
	assert.Equal(t, "Unknown", Version(0).String())
	assert.Equal(t, "Unknown", Version(99).String())
}

// Test_AuthServers_FingerprintInvalidation pins the contract that
// callers must invalidate the cached fingerprint before releasing the
// write lock: reading Fingerprint() after the mutation but before
// InvalidateFingerprint() returned a stale hash in the old shape.
func Test_AuthServers_FingerprintInvalidation(t *testing.T) {
	s := &AuthServers{}
	s.List = append(s.List, NewAuthServer("1.1.1.1:53", IPv4))
	first := s.Fingerprint()
	assert.NotZero(t, first)

	// Same state → same fingerprint.
	assert.Equal(t, first, s.Fingerprint())

	// Mutate and invalidate; new fingerprint must differ.
	s.Lock()
	s.List = append(s.List, NewAuthServer("2.2.2.2:53", IPv4))
	s.InvalidateFingerprint()
	s.Unlock()
	second := s.Fingerprint()
	assert.NotEqual(t, first, second)
}

// Test_AuthServers_FingerprintMutationRace simulates the interleaving
// where a mutator invalidates between a reader's snapshot and its
// cache-store. With the generation-counter protection the reader
// refuses to publish the outdated hash, so the next call returns the
// fresh state instead of the revived stale one.
func Test_AuthServers_FingerprintMutationRace(t *testing.T) {
	s := &AuthServers{}
	s.List = append(s.List, NewAuthServer("1.1.1.1:53", IPv4))

	// Manually reproduce the race sequence: snapshot the gen the
	// reader would observe, mutate List and bump the generation as a
	// writer would, and then attempt to store the "stale" pair. The
	// store must be refused because gen no longer matches.
	gen := s.gen.Load()
	staleFP := uint64(0xdeadbeef) // a value the genuine hash cannot equal here

	s.Lock()
	s.List = append(s.List, NewAuthServer("2.2.2.2:53", IPv4))
	s.InvalidateFingerprint()
	s.Unlock()

	// Simulate the reader's late publish attempt.
	if s.gen.Load() == gen {
		s.fpCache.Store(&fpEntry{gen: gen, fp: staleFP})
	}

	got := s.Fingerprint()
	assert.NotEqual(t, staleFP, got, "stale fingerprint must not be served after mutation")
}

func Test_AuthServerString(t *testing.T) {
	// Test UNKNOWN health (Rtt <= 0)
	s := NewAuthServer("1.2.3.4:53", IPv4)
	str := s.String()
	assert.Contains(t, str, "IPv4")
	assert.Contains(t, str, "1.2.3.4:53")
	assert.Contains(t, str, "UNKNOWN")

	// Test GOOD health (0 < Rtt < 1 second)
	s.Rtt = int64(100 * time.Millisecond)
	s.Count = 1
	str = s.String()
	assert.Contains(t, str, "GOOD")

	// Test POOR health (Rtt >= 1 second)
	s.Rtt = int64(2 * time.Second)
	s.Count = 1
	str = s.String()
	assert.Contains(t, str, "POOR")
}
