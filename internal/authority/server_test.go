package authority

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// serverReference mirrors Server's layout — types and order, which is all
// a size comparison depends on; the names are exported only so a linter
// does not read a layout mirror as dead code.
//
// serverReference is what a Server is allowed to weigh: the scoring words
// the ranking reads, the address, and the pre-parsed form the exchange
// dials. It is written out rather than asserted as a byte count so the
// claim survives a change of ABI — and so the next field to arrive has to
// be added here, deliberately, next to the ones that earned their space.
type serverReference struct {
	Rtt       int64
	Count     int64
	LastNs    int64
	Addr      string
	Fails     int32
	IPVersion IPVersion
	Canonical bool
	UDPAddr   *net.UDPAddr
}

// TestServerLayoutStaysSmall prices this struct. There is one Server per
// authority per delegation, allocated as the resolver reads referrals and
// retained for as long as the delegation is cached, so a field that pushes
// it into the next size class is paid continuously and at scale.
//
// Two of the scoring fields are free: canonical and fails both ride in the
// padding IPVersion already leaves. lastNs is the one word the ranking
// bought, and it replaced a periodic wipe of every server's statistics —
// evidence that ages per server instead of a moment where the whole set
// reads as unmeasured at once.
func TestServerLayoutStaysSmall(t *testing.T) {
	want := unsafe.Sizeof(serverReference{})
	if got := unsafe.Sizeof(Server{}); got != want {
		t.Fatalf("Server is %d B against a reference of %d B; a field left "+
			"the padding IPVersion shares", got, want)
	}
}

func Test_TrySort(t *testing.T) {
	s := &Servers{
		List: []*Server{},
	}

	for i := 0; i < 10; i++ {
		s.List = append(s.List, NewServer(fmt.Sprintf("0.0.0.%d:53", i), IPv4))
		s.List = append(s.List, NewServer(fmt.Sprintf("[::%d]:53", i), IPv6))
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // G404 - test file, not used for crypto
	for range 2000 {
		for j := range s.List {
			s.List[j].Observe(time.Duration(r.Intn(2000)) * time.Millisecond)
			Sort(s.List)
		}
	}

	// The leader is the cheapest server in the set. Only the hedge slot
	// behind it is chosen at random, so this holds however the samples
	// fell.
	lead := s.List[0].Score()
	for _, srv := range s.List[1:] {
		if srv.Score() < lead {
			t.Fatalf("%s scores %v, ahead of the leader %s at %v",
				srv.Addr, srv.Score(), s.List[0].Addr, lead)
		}
	}
}

func Test_VersionString(t *testing.T) {
	if !reflect.DeepEqual("IPv4", IPv4.String()) {
		t.Errorf("IPv4.String() = %v, want %v", IPv4.String(), "IPv4")
	}
	if !reflect.DeepEqual("IPv6", IPv6.String()) {
		t.Errorf("IPv6.String() = %v, want %v", IPv6.String(), "IPv6")
	}
	if !reflect.DeepEqual("Unknown", IPVersion(0).String()) {
		t.Errorf("IPVersion(0).String() = %v, want %v", IPVersion(0).String(), "Unknown")
	}
	if !reflect.DeepEqual("Unknown", IPVersion(99).String()) {
		t.Errorf("IPVersion(99).String() = %v, want %v", IPVersion(99).String(), "Unknown")
	}
}

// Test_Servers_FingerprintInvalidation pins the contract that
// callers must invalidate the cached fingerprint before releasing the
// write lock: reading Fingerprint() after the mutation but before
// InvalidateFingerprint() returned a stale hash in the old shape.
func Test_Servers_FingerprintInvalidation(t *testing.T) {
	s := &Servers{}
	s.List = append(s.List, NewServer("1.1.1.1:53", IPv4))
	first := s.Fingerprint()
	if first == 0 {
		t.Error("first is zero")
	}

	// Same state → same fingerprint.
	if !reflect.DeepEqual(first, s.Fingerprint()) {
		t.Errorf("s.Fingerprint() = %v, want %v", s.Fingerprint(), first)
	}

	// Mutate and invalidate; new fingerprint must differ.
	s.Lock()
	s.List = append(s.List, NewServer("2.2.2.2:53", IPv4))
	s.InvalidateFingerprint()
	s.Unlock()
	second := s.Fingerprint()
	if reflect.DeepEqual(first, second) {
		t.Errorf("second = %v, want a different value", second)
	}
}

// Test_Servers_FingerprintMutationRace simulates the interleaving
// where a mutator invalidates between a reader's snapshot and its
// cache-store. With the generation-counter protection the reader
// refuses to publish the outdated hash, so the next call returns the
// fresh state instead of the revived stale one.
func Test_Servers_FingerprintMutationRace(t *testing.T) {
	s := &Servers{}
	s.List = append(s.List, NewServer("1.1.1.1:53", IPv4))

	// Manually reproduce the race sequence: snapshot the gen the
	// reader would observe, mutate List and bump the generation as a
	// writer would, and then attempt to store the "stale" pair. The
	// store must be refused because gen no longer matches.
	gen := s.gen.Load()
	staleFP := uint64(0xdeadbeef) // a value the genuine hash cannot equal here

	s.Lock()
	s.List = append(s.List, NewServer("2.2.2.2:53", IPv4))
	s.InvalidateFingerprint()
	s.Unlock()

	// Simulate the reader's late publish attempt.
	if s.gen.Load() == gen {
		s.fpCache.Store(&fpEntry{gen: gen, fp: staleFP})
	}

	got := s.Fingerprint()
	if reflect.DeepEqual(staleFP, got) {
		t.Errorf("%s: got = %v, want a different value", "stale fingerprint must not be served after mutation", got)
	}
}

func Test_ServerString(t *testing.T) {
	// Test UNKNOWN health (Rtt <= 0)
	s := NewServer("1.2.3.4:53", IPv4)
	str := s.String()
	if !strings.Contains(str, "IPv4") {
		t.Errorf("%q does not contain %q", str, "IPv4")
	}
	if !strings.Contains(str, "1.2.3.4:53") {
		t.Errorf("%q does not contain %q", str, "1.2.3.4:53")
	}
	if !strings.Contains(str, "UNKNOWN") {
		t.Errorf("%q does not contain %q", str, "UNKNOWN")
	}

	// Test GOOD health (0 < Rtt < 1 second)
	s.Rtt = int64(100 * time.Millisecond)
	s.Count = 1
	str = s.String()
	if !strings.Contains(str, "GOOD") {
		t.Errorf("%q does not contain %q", str, "GOOD")
	}

	// Test POOR health (Rtt >= 1 second)
	s.Rtt = int64(2 * time.Second)
	s.Count = 1
	str = s.String()
	if !strings.Contains(str, "POOR") {
		t.Errorf("%q does not contain %q", str, "POOR")
	}
}

// TestNewServerCanonicalizes directly pins the canonical Addr contract every
// comparison site and map key now depends on: IPv6 case/compression collapse
// to one spelling, 4-in-6 addresses unmap to plain IPv4, and the pre-parsed
// UDPAddr survives construction on every literal path.
func TestNewServerCanonicalizes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.0.2.1:53", "192.0.2.1:53"},
		{"[::ffff:192.0.2.7]:53", "192.0.2.7:53"}, // 4-in-6 unmapped
		{"[2001:DB8::A]:53", "[2001:db8::a]:53"},  // case + compression
		{"[2001:db8:0:0:0:0:0:a]:53", "[2001:db8::a]:53"},
	}
	for _, tc := range cases {
		s := NewServer(tc.in, IPv4)
		if s.Addr != tc.want {
			t.Fatalf("NewServer(%q).Addr = %q, want %q", tc.in, s.Addr, tc.want)
		}
		if s.UDPAddr == nil {
			t.Fatalf("NewServer(%q) lost the pre-parsed UDPAddr", tc.in)
		}
	}

	// Spelling variants must also converge through NewServerFromAddrPort,
	// including its family derivation.
	ap := NewServerFromAddrPort(netip.MustParseAddrPort("[::ffff:198.51.100.4]:53"))
	if ap.Addr != "198.51.100.4:53" || ap.IPVersion != IPv4 {
		t.Fatalf("AddrPort construction = %q/%v, want unmapped IPv4", ap.Addr, ap.IPVersion)
	}
	if v6 := NewServerFromAddrPort(netip.MustParseAddrPort("[2001:DB8::1]:53")); v6.IPVersion != IPv6 {
		t.Fatalf("IPv6 family derivation = %v", v6.IPVersion)
	}
}
