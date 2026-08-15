package ipset

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"testing"
)

func mustSet(t *testing.T, cidrs ...string) *Set {
	t.Helper()
	s, bad := New(cidrs)
	if len(bad) > 0 {
		t.Fatalf("unexpected bad entries: %v", bad)
	}
	return s
}

func TestContains(t *testing.T) {
	cases := []struct {
		name  string
		cidrs []string
		addr  string
		want  bool
	}{
		{"v4 default route takes everything v4", []string{"0.0.0.0/0"}, "192.0.2.44", true},
		{"v4 default route is not a v6 route", []string{"0.0.0.0/0"}, "2001:db8::1", false},
		{"v6 default route takes everything v6", []string{"::/0"}, "2001:db8::1", true},
		{"v6 default route is not a v4 route", []string{"::/0"}, "192.0.2.44", false},
		{"first address of the block", []string{"192.0.2.0/24"}, "192.0.2.0", true},
		{"last address of the block", []string{"192.0.2.0/24"}, "192.0.2.255", true},
		{"one past the block", []string{"192.0.2.0/24"}, "192.0.3.0", false},
		{"one before the block", []string{"192.0.2.0/24"}, "192.0.1.255", false},
		{"single host in", []string{"192.0.2.7/32"}, "192.0.2.7", true},
		{"single host out", []string{"192.0.2.7/32"}, "192.0.2.8", false},
		{"host bits are masked away", []string{"192.0.2.5/24"}, "192.0.2.99", true},
		{"v6 block, last address", []string{"2001:db8::/32"}, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"v6 block, one past", []string{"2001:db8::/32"}, "2001:db9::", false},
		{"v6 single host", []string{"2001:db8::1/128"}, "2001:db8::1", true},
		{"v6 half-width boundary", []string{"2001:db8::/64"}, "2001:db8::ffff:ffff:ffff:ffff", true},
		{"v6 half-width, one past", []string{"2001:db8::/64"}, "2001:db8:0:1::", false},
		{"nested blocks, outer match", []string{"10.0.0.0/8", "10.1.2.0/24"}, "10.9.9.9", true},
		{"nested blocks, inner match", []string{"10.0.0.0/8", "10.1.2.0/24"}, "10.1.2.3", true},
		{"a later small block does not hide an earlier large one",
			[]string{"10.0.0.0/8", "10.255.0.0/16"}, "10.200.0.1", true},
		{"outside every block", []string{"10.0.0.0/8", "192.168.0.0/16"}, "172.16.0.1", false},
		{"mixed families, v4 client", []string{"::/0", "192.0.2.0/24"}, "192.0.2.1", true},
		{"mixed families, v6 client", []string{"0.0.0.0/0", "2001:db8::/32"}, "2001:db8::5", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustSet(t, tc.cidrs...)
			addr := netip.MustParseAddr(tc.addr)
			if got := s.Contains(addr); got != tc.want {
				t.Fatalf("Contains(%s) in %v = %v, want %v", tc.addr, tc.cidrs, got, tc.want)
			}
		})
	}
}

func TestEmptySetContainsNothing(t *testing.T) {
	var s Set
	if s.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("the zero value matched an address")
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d, want 0", s.Len())
	}
}

// A client arriving on a dual-stack socket is presented as an
// IPv4-mapped address. An operator who wrote an IPv4 CIDR means it to
// match that client.
func TestMappedAddressIsAnsweredAsIPv4(t *testing.T) {
	s := mustSet(t, "192.0.2.0/24")
	mapped := netip.MustParseAddr("::ffff:192.0.2.5")
	if !s.Contains(mapped) {
		t.Fatal("an IPv4-mapped client did not match the IPv4 block it came from")
	}
	if !s.ContainsIP(net.ParseIP("192.0.2.5")) {
		t.Fatal("net.IP form did not match")
	}
	// net.ParseIP returns 16-byte form for v4 literals; that must not
	// change the answer either.
	if !s.ContainsIP(net.ParseIP("::ffff:192.0.2.5")) {
		t.Fatal("16-byte v4 form did not match")
	}
}

func TestBadEntriesAreReportedNotFatal(t *testing.T) {
	s, bad := New([]string{"10.0.0.0/8", "not-a-cidr", "10.0.0.0/33", "192.168.0.0/16"})
	if len(bad) != 2 {
		t.Fatalf("bad = %v, want the two malformed entries", bad)
	}
	if bad[0].CIDR != "not-a-cidr" || bad[0].Error() == "" {
		t.Fatalf("unexpected first bad entry: %+v", bad[0])
	}
	if !s.Contains(netip.MustParseAddr("10.1.1.1")) || !s.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("a typo in one entry knocked out the rest of the list")
	}
}

func TestInvalidAddressMatchesNothing(t *testing.T) {
	s := mustSet(t, "0.0.0.0/0", "::/0")
	if s.Contains(netip.Addr{}) {
		t.Fatal("the zero address matched a default route")
	}
	if s.ContainsIP(nil) {
		t.Fatal("a nil net.IP matched")
	}
	if s.ContainsIP(net.IP{1, 2, 3}) {
		t.Fatal("a malformed net.IP matched")
	}
}

// The lookup runs before the cache on every query. It has to cost
// nothing, which is the whole reason this package exists.
func TestContainsAllocatesNothing(t *testing.T) {
	s := mustSet(t, "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32", "0.0.0.0/0")
	v4 := netip.MustParseAddr("192.0.2.44")
	v6 := netip.MustParseAddr("2001:db8::1")
	ip := net.ParseIP("192.0.2.44")

	if n := testing.AllocsPerRun(500, func() {
		if !s.Contains(v4) || !s.Contains(v6) {
			t.Fatal("miss")
		}
	}); n != 0 {
		t.Fatalf("Contains allocated %.1f objects per call", n)
	}
	if n := testing.AllocsPerRun(500, func() {
		if !s.ContainsIP(ip) {
			t.Fatal("miss")
		}
	}); n != 0 {
		t.Fatalf("ContainsIP allocated %.1f objects per call", n)
	}
}

// Against the standard library, over random lists and random addresses:
// the structure is an optimization, so it has to agree with the obvious
// implementation everywhere, not just on the cases someone thought of.
func TestAgreesWithNetIPNet(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic fixture data, not a secret
	for round := 0; round < 200; round++ {
		var cidrs []string
		var nets []*net.IPNet
		count := 1 + rng.Intn(12)
		for i := 0; i < count; i++ {
			var cidr string
			if rng.Intn(2) == 0 {
				cidr = netip.PrefixFrom(randV4(rng), rng.Intn(33)).Masked().String()
			} else {
				cidr = netip.PrefixFrom(randV6(rng), rng.Intn(129)).Masked().String()
			}
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("generated an unparseable cidr %q: %v", cidr, err)
			}
			cidrs = append(cidrs, cidr)
			nets = append(nets, n)
		}
		s := mustSet(t, cidrs...)

		for probe := 0; probe < 64; probe++ {
			var addr netip.Addr
			if rng.Intn(2) == 0 {
				addr = randV4(rng)
			} else {
				addr = randV6(rng)
			}
			// Bias towards addresses near the configured blocks, where
			// off-by-one errors live.
			if probe%2 == 0 && len(nets) > 0 {
				pick := nets[rng.Intn(len(nets))]
				near, ok := netip.AddrFromSlice(pick.IP)
				if ok {
					near = near.Unmap()
					for shift := rng.Intn(3); shift > 0; shift-- {
						near = near.Next()
					}
					if rng.Intn(2) == 0 {
						near = near.Prev()
					}
					if near.IsValid() {
						addr = near
					}
				}
			}

			want := false
			for _, n := range nets {
				if n.Contains(net.IP(addr.AsSlice())) {
					want = true
					break
				}
			}
			if got := s.Contains(addr); got != want {
				t.Fatalf("Contains(%s) = %v, want %v; list %v", addr, got, want, cidrs)
			}
		}
	}
}

func randV4(rng *rand.Rand) netip.Addr {
	var b [4]byte
	_, _ = rng.Read(b[:])
	return netip.AddrFrom4(b)
}

func randV6(rng *rand.Rand) netip.Addr {
	var b [16]byte
	_, _ = rng.Read(b[:])
	return netip.AddrFrom16(b)
}

func BenchmarkContains(b *testing.B) {
	sizes := []int{2, 16, 256}
	for _, n := range sizes {
		var cidrs []string
		for i := 0; i < n; i++ {
			cidrs = append(cidrs, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24).String())
		}
		cidrs = append(cidrs, "192.0.2.0/24")
		s, _ := New(cidrs)
		addr := netip.MustParseAddr("192.0.2.44")
		b.Run(fmt.Sprintf("%dprefixes", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !s.Contains(addr) {
					b.Fatal("miss")
				}
			}
		})
	}
}
