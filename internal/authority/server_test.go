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

// serverWithoutCanonical is Server as it stood before it recorded whether its
// address is canonical. It is the reference the size test compares against, so
// the claim being made is "the marker is free" rather than a byte count that
// is only true on one ABI.
type serverWithoutCanonical struct {
	State     int64
	LastNs    int64
	Addr      string
	IPVersion IPVersion
	UDPAddr   *net.UDPAddr
}

// TestServerLayoutStaysSmall pins that knowing an address is canonical costs
// nothing. There is one Server per authority per delegation and they are
// allocated as the resolver reads referrals, so a field that pushes this into
// the next size class is paid for continuously; canonical fits in the padding
// IPVersion already leaves.
func TestServerLayoutStaysSmall(t *testing.T) {
	want := unsafe.Sizeof(serverWithoutCanonical{})
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
	for i := 0; i < 2000; i++ {
		for j := range s.List {
			s.List[j].Observe(time.Duration(r.Intn(2000)) * time.Millisecond)
			Sort(s.List)
		}
	}

	// However the samples fell, the head of the list is the cheapest
	// server in it. The old shape could not promise this: every thousandth
	// sort wiped every server's statistics, and for the sorts that
	// followed the whole set read as unmeasured, which it ranked first.
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

	// Test GOOD health (a measured, sub-second latency)
	s.Observe(100 * time.Millisecond)
	str = s.String()
	if !strings.Contains(str, "GOOD") {
		t.Errorf("%q does not contain %q", str, "GOOD")
	}

	// Test POOR health (a measured latency past a second). The blend is
	// half and half, so this lands at 2.05s.
	s.Observe(4 * time.Second)
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
