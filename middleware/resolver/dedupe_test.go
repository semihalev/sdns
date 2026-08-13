package resolver

import (
	"net/netip"
	"testing"

	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/middleware"
)

// authorityServers builds a delegation's worth of servers the way the
// resolver's own producers do — from decoded glue addresses.
func authorityServers(tb testing.TB, count int) []*authority.Server {
	tb.Helper()
	servers := make([]*authority.Server, 0, count)
	for i := range count {
		addr := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 53)
		servers = append(servers, authority.NewServerFromAddrPort(addr))
	}
	return servers
}

func serverAddrs(servers []*authority.Server) []string {
	addrs := make([]string, 0, len(servers))
	for _, s := range servers {
		addrs = append(addrs, s.Addr)
	}
	return addrs
}

func TestDedupeAuthorityServers(t *testing.T) {
	t.Run("keeps first occurrence and order", func(t *testing.T) {
		servers := authorityServers(t, 3)
		input := []*authority.Server{
			servers[2], servers[0], servers[2], servers[1], servers[0],
		}
		got := serverAddrs(dedupeAuthorityServers(input))
		want := []string{servers[2].Addr, servers[0].Addr, servers[1].Addr}
		if len(got) != len(want) {
			t.Fatalf("deduped to %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("deduped to %v, want %v", got, want)
			}
		}
	})

	t.Run("drops nil entries", func(t *testing.T) {
		servers := authorityServers(t, 2)
		got := dedupeAuthorityServers(
			[]*authority.Server{nil, servers[0], nil, servers[1], nil})
		if len(got) != 2 {
			t.Fatalf("deduped to %d servers, want 2", len(got))
		}
	})

	t.Run("distinct pointers with one address collapse", func(t *testing.T) {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 53)
		got := dedupeAuthorityServers([]*authority.Server{
			authority.NewServerFromAddrPort(addr),
			authority.NewServerFromAddrPort(addr),
		})
		if len(got) != 1 {
			t.Fatalf("two servers for one address deduped to %d, want 1", len(got))
		}
	})

	t.Run("a non-literal address still dedupes", func(t *testing.T) {
		// No netip identity to compare, so these fall back to the
		// canonical-spelling path.
		got := dedupeAuthorityServers([]*authority.Server{
			authority.NewServer("NS1.Example.Com:53", authority.IPv4),
			authority.NewServer("ns1.example.com:53", authority.IPv4),
		})
		if len(got) != 1 {
			t.Fatalf("one host under two spellings deduped to %d, want 1", len(got))
		}
	})

	t.Run("across the linear/indexed threshold", func(t *testing.T) {
		// The threshold is on the input length, so the corpus has to be
		// exactly that long: duplicates come from repeating servers within
		// it, not from lengthening it.
		for _, count := range []int{
			linearDedupeLimit - 1, linearDedupeLimit, linearDedupeLimit + 1,
		} {
			unique := authorityServers(t, (count+1)/2)
			corpus := make([]*authority.Server, count)
			for i := range corpus {
				// Repeats interleaved with first occurrences, so order is
				// something the implementations can disagree about.
				corpus[i] = unique[(i*3)%len(unique)]
			}
			if len(corpus) != count {
				t.Fatalf("fixture is wrong: corpus is %d long, want %d",
					len(corpus), count)
			}

			// Both implementations run on the same corpus, each on its own
			// copy since they dedupe in place.
			linear := serverAddrs(dedupeAuthorityServersLinear(
				append([]*authority.Server(nil), corpus...)))
			indexed := serverAddrs(dedupeAuthorityServersIndexed(
				append([]*authority.Server(nil), corpus...)))
			chosen := serverAddrs(dedupeAuthorityServers(
				append([]*authority.Server(nil), corpus...)))

			if len(linear) != len(indexed) {
				t.Fatalf("at %d servers: linear kept %d, indexed kept %d",
					count, len(linear), len(indexed))
			}
			// Length before contents: a wrapper that dropped nothing would
			// still match on every position the shorter result has.
			if len(chosen) != len(linear) {
				t.Fatalf("at %d servers: the threshold kept %d, both "+
					"implementations kept %d",
					count, len(chosen), len(linear))
			}
			for i := range linear {
				if linear[i] != indexed[i] {
					t.Fatalf("at %d servers, position %d: linear %q, "+
						"indexed %q", count, i, linear[i], indexed[i])
				}
				if chosen[i] != linear[i] {
					t.Fatalf("at %d servers, position %d: the threshold "+
						"picked %q, both implementations say %q",
						count, i, chosen[i], linear[i])
				}
			}
		}
	})

	t.Run("empty and single", func(t *testing.T) {
		if got := dedupeAuthorityServers(nil); len(got) != 0 {
			t.Fatalf("nil deduped to %d servers", len(got))
		}
		one := authorityServers(t, 1)
		if got := dedupeAuthorityServers(one); len(got) != 1 {
			t.Fatalf("one server deduped to %d", len(got))
		}
	})
}

// TestDedupeAuthorityServersDoesNotAllocate pins the delegation-sized case.
// Every lookup dedupes its authority list, the addresses were canonical the
// moment they were decoded, and re-deriving that identity per server per
// lookup was the second-largest allocation site in the resolver.
func TestDedupeAuthorityServersDoesNotAllocate(t *testing.T) {
	for _, count := range []int{2, 8, 13} {
		servers := authorityServers(t, count)
		input := make([]*authority.Server, len(servers))

		allocs := testing.AllocsPerRun(200, func() {
			copy(input, servers)
			if got := dedupeAuthorityServers(input); len(got) != count {
				t.Fatalf("%d servers deduped to %d", count, len(got))
			}
		})
		if allocs != 0 {
			t.Fatalf("deduping %d servers cost %.0f allocations", count, allocs)
		}
	}
}

// TestServerAddrIsAlreadyCanonical pins the promise the retry guard's fast
// path is built on.
//
// queryServer hands Addr to BeginCanonical instead of normalizing it, which is
// only sound while a server carrying a decoded Endpoint spells that endpoint
// exactly as CanonicalResolutionEndpoint would. If a constructor ever stored a
// different spelling, one tuple would count under two keys and the RFC 9520
// attempt limit would admit twice what it should — silently.
func TestServerAddrIsAlreadyCanonical(t *testing.T) {
	for _, spelling := range []string{
		"192.0.2.1:53",
		"[2001:db8::1]:53",
		// 4-in-6 and an uppercase v6 literal: both are addresses the
		// constructor is expected to fold.
		"[::ffff:192.0.2.1]:53",
		"[2001:DB8::1]:53",
		"[2001:db8:0:0:0:0:0:1]:53",
	} {
		for _, server := range []*authority.Server{
			authority.NewServer(spelling, authority.IPv4),
			mustServerFromSpelling(t, spelling),
		} {
			addr, canonical := server.CanonicalAddr()
			if !canonical {
				t.Fatalf("%q was not recognized as a canonical address", spelling)
			}
			if got := middleware.CanonicalResolutionEndpoint(addr); got != addr {
				t.Fatalf("%q stored Addr %q, which canonicalizes to %q; the "+
					"guard's fast path would key it under two identities",
					spelling, addr, got)
			}
		}
	}
}

func mustServerFromSpelling(tb testing.TB, spelling string) *authority.Server {
	tb.Helper()
	ap, err := netip.ParseAddrPort(spelling)
	if err != nil {
		tb.Fatalf("ParseAddrPort(%q): %v", spelling, err)
	}
	return authority.NewServerFromAddrPort(ap)
}

func BenchmarkDedupeAuthorityServers(b *testing.B) {
	for _, count := range []int{2, 4, 13, 64} {
		servers := authorityServers(b, count)
		input := make([]*authority.Server, len(servers))
		b.Run(serverCountName(count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				copy(input, servers)
				dedupeAuthorityServers(input)
			}
		})
	}
}

func serverCountName(count int) string {
	switch count {
	case 2:
		return "servers=2"
	case 4:
		return "servers=4"
	case 13:
		return "servers=13"
	default:
		return "servers=64"
	}
}
