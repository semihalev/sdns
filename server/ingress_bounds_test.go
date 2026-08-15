package server

import (
	"testing"
)

// The bounds are derived because the machines differ. This checks the
// curve at both ends — the router the author never saw and the server the
// number was originally written for — rather than the one value this
// build happens to compute here.
func TestIngressBoundsFollowTheMachine(t *testing.T) {
	const (
		mib = 1 << 20
		gib = 1 << 30
	)
	cases := []struct {
		name           string
		budget         uint64
		wantSpare      int
		wantConns      int
		spareAtMost    int
		connsAtMost    int
		spareAtLeast   int
		connsAtLeast   int
		exactlyClamped bool
	}{
		{name: "128MB router", budget: 128 * mib, spareAtMost: 512, connsAtMost: 256,
			spareAtLeast: minSpareSlabs, connsAtLeast: minTCPConns},
		{name: "512MB appliance", budget: 512 * mib, spareAtMost: 2048, connsAtMost: 1024,
			spareAtLeast: 512, connsAtLeast: 256},
		{name: "2GB VPS", budget: 2 * gib, spareAtMost: maxSpareSlabs, connsAtMost: maxTCPConns,
			spareAtLeast: 2048, connsAtLeast: 1024},
		{name: "32GB server", budget: 32 * gib, wantSpare: maxSpareSlabs, wantConns: maxTCPConns,
			exactlyClamped: true},
		{name: "unknown platform", budget: 0, wantSpare: boundFor(unknownMemoryBudget, udpSpareBytes, minSpareSlabs, maxSpareSlabs),
			wantConns: boundFor(unknownMemoryBudget, tcpConnBytes, minTCPConns, maxTCPConns), exactlyClamped: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spare := boundFor(tc.budget, udpSpareBytes, minSpareSlabs, maxSpareSlabs)
			conns := boundFor(tc.budget, tcpConnBytes, minTCPConns, maxTCPConns)

			if tc.exactlyClamped {
				if spare != tc.wantSpare || conns != tc.wantConns {
					t.Fatalf("spare=%d conns=%d, want %d/%d", spare, conns, tc.wantSpare, tc.wantConns)
				}
				return
			}
			if spare < tc.spareAtLeast || spare > tc.spareAtMost {
				t.Fatalf("spare slabs = %d, want between %d and %d on %s",
					spare, tc.spareAtLeast, tc.spareAtMost, tc.name)
			}
			if conns < tc.connsAtLeast || conns > tc.connsAtMost {
				t.Fatalf("tcp conns = %d, want between %d and %d on %s",
					conns, tc.connsAtLeast, tc.connsAtMost, tc.name)
			}
		})
	}
}

// However little memory a machine reports, the bound stays inside its
// floor and ceiling: a server with no room is still a server, and a
// machine that reports something absurd does not get an absurd bound.
func TestIngressBoundsStayWithinTheirLimits(t *testing.T) {
	budgets := []uint64{0, 1, 4 << 10, 64 << 20, 1 << 40, ^uint64(0)}
	for _, budget := range budgets {
		spare := boundFor(budget, udpSpareBytes, minSpareSlabs, maxSpareSlabs)
		if spare < minSpareSlabs || spare > maxSpareSlabs {
			t.Fatalf("budget %d gave %d spare slabs, outside [%d,%d]",
				budget, spare, minSpareSlabs, maxSpareSlabs)
		}
		conns := boundFor(budget, tcpConnBytes, minTCPConns, maxTCPConns)
		if conns < minTCPConns || conns > maxTCPConns {
			t.Fatalf("budget %d gave %d connections, outside [%d,%d]",
				budget, conns, minTCPConns, maxTCPConns)
		}
	}
}

// The worst case the bounds allow has to stay a fraction of what the
// process may use — that is the whole point of deriving them.
func TestIngressWorstCaseFitsTheBudget(t *testing.T) {
	for _, budget := range []uint64{128 << 20, 512 << 20, 2 << 30, 32 << 30} {
		spare := boundFor(budget, udpSpareBytes, minSpareSlabs, maxSpareSlabs)
		conns := boundFor(budget, tcpConnBytes, minTCPConns, maxTCPConns)
		worst := uint64(spare)*udpSpareBytes + uint64(conns)*tcpConnBytes //nolint:gosec // both are clamped positives
		if share := float64(worst) / float64(budget); share > 0.15 {
			t.Fatalf("on %d bytes the front door could reach %d bytes (%.0f%%); "+
				"the cache, the resolver and the runtime need the rest",
				budget, worst, share*100)
		}
	}
}

// What this machine decided, for the record: a failure here is a machine
// the derivation has not been thought about on, not a broken build.
func TestIngressBoundsOnThisMachine(t *testing.T) {
	t.Logf("memory budget %d bytes -> %d spare slabs, %d connections",
		memoryBudget(), spareSlabBound, tcpConnBound())
	if spareSlabBound < minSpareSlabs || spareSlabBound > maxSpareSlabs {
		t.Fatalf("spare bound %d outside [%d,%d]", spareSlabBound, minSpareSlabs, maxSpareSlabs)
	}
	if c := tcpConnBound(); c < minTCPConns || c > maxTCPConns {
		t.Fatalf("connection bound %d outside [%d,%d]", c, minTCPConns, maxTCPConns)
	}
}
