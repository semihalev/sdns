package server

import (
	"testing"
)

const (
	mib = 1 << 20
	gib = 1 << 30
)

// The plan is derived because the machines differ. This checks the curve
// at both ends, the router the author never saw and the server the
// numbers were originally measured on, rather than the one value this
// build happens to compute here.
func TestResourcePlanFollowsTheMachine(t *testing.T) {
	cases := []struct {
		name string
		in   planInputs

		workers   int
		largeJobs int

		spareAtLeast, spareAtMost int64
		connsAtLeast, connsAtMost int
	}{
		{
			name:    "128MB router, 4 cores",
			in:      planInputs{budget: 128 * mib, cpus: 4, streamEngines: 2, sockets: 4},
			workers: 64, largeJobs: 4,
			spareAtLeast: 64, spareAtMost: 512,
			connsAtLeast: 8, connsAtMost: 128,
		},
		{
			// The container case: the cgroup is small, the host is not.
			// Workers and sockets follow the memory, never the cores,
			// measured on a 32-core box, where a 128MB scope was otherwise
			// given 512 workers and a slab cap to match.
			name:    "128MB cgroup on a 32-core host",
			in:      planInputs{budget: 128 * mib, cpus: 32, streamEngines: 1, sockets: 16},
			workers: 64, largeJobs: 4,
			spareAtLeast: 64, spareAtMost: 512,
			connsAtLeast: 8, connsAtMost: 256,
		},
		{
			name:    "512MB appliance, 2 cores",
			in:      planInputs{budget: 512 * mib, cpus: 2, streamEngines: 1, sockets: 2},
			workers: 128, largeJobs: defaultTCPLargeJobs / 2,
			spareAtLeast: 512, spareAtMost: 2048,
			connsAtLeast: 128, connsAtMost: 1024,
		},
		{
			name:    "32GB server, 32 cores",
			in:      planInputs{budget: 32 * gib, cpus: 32, streamEngines: 1, sockets: 16},
			workers: 512, largeJobs: defaultTCPLargeJobs,
			spareAtLeast: maxSpareSlabs, spareAtMost: maxSpareSlabs,
			connsAtLeast: maxTCPConns, connsAtMost: maxTCPConns,
		},
		{
			name:    "unknown platform is treated as modest",
			in:      planInputs{budget: 0, cpus: 8, streamEngines: 1, sockets: 1},
			workers: 128, largeJobs: defaultTCPLargeJobs / 2,
			spareAtLeast: 512, spareAtMost: 2048,
			connsAtLeast: 128, connsAtMost: 1024,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := computeResourcePlan(tc.in)
			if p.udpWorkers != tc.workers {
				t.Fatalf("workers = %d, want %d", p.udpWorkers, tc.workers)
			}
			if p.tcpLargeJobs != tc.largeJobs {
				t.Fatalf("large jobs = %d, want %d", p.tcpLargeJobs, tc.largeJobs)
			}
			if p.udpSpareSlabs < tc.spareAtLeast || p.udpSpareSlabs > tc.spareAtMost {
				t.Fatalf("spare slabs = %d, want within [%d,%d]", p.udpSpareSlabs, tc.spareAtLeast, tc.spareAtMost)
			}
			if p.tcpConns < tc.connsAtLeast || p.tcpConns > tc.connsAtMost {
				t.Fatalf("conns = %d, want within [%d,%d]", p.tcpConns, tc.connsAtLeast, tc.connsAtMost)
			}
			if p.tcpSmallJobs > p.tcpConns && p.tcpConns >= 1 {
				t.Fatalf("small jobs %d exceed conns %d", p.tcpSmallJobs, p.tcpConns)
			}
			if p.udpQueue != defaultIngressQueue {
				t.Fatalf("queue = %d, want %d", p.udpQueue, defaultIngressQueue)
			}
		})
	}
}

// The budget is charged what the bounds can actually cost, every slab
// class at its real allocator size, the large pairs included, both
// stream engines counted. The old arithmetic priced only spares and
// connections and understated a 64MiB TCP+DoT deployment by more than
// half.
func TestBudgetChargesRealCosts(t *testing.T) {
	cases := []struct {
		name    string
		in      planInputs
		atMost  int64 // worst case, real prices
		comment string
	}{
		{
			name:   "64MiB with TCP and DoT",
			in:     planInputs{budget: 64 * mib, cpus: 4, streamEngines: 2, sockets: 4},
			atMost: 10 * mib, // floors dominate here; stated, not hidden
		},
		{
			name:   "128MiB with TCP and DoT",
			in:     planInputs{budget: 128 * mib, cpus: 4, streamEngines: 2, sockets: 4},
			atMost: 16 * mib,
		},
		{
			name:   "512MiB single engine",
			in:     planInputs{budget: 512 * mib, cpus: 4, streamEngines: 1, sockets: 4},
			atMost: 40 * mib,
		},
		{
			name:   "32GiB server",
			in:     planInputs{budget: 32 * gib, cpus: 32, streamEngines: 2, sockets: 16},
			atMost: 512 * mib,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := computeResourcePlan(tc.in)
			worst := p.worstCaseBytes(tc.in.streamEngines)
			if worst > tc.atMost {
				t.Fatalf("worst case %d bytes (%.1f MiB) exceeds %d", worst,
					float64(worst)/mib, tc.atMost)
			}
			// Above the floor regime the worst case must stay inside the
			// front door's documented share of the budget.
			if tc.in.budget >= 512*mib {
				share := int64(tc.in.budget) / (ingressMemoryShare / 4) //nolint:gosec // test budgets are small
				if worst > share {
					t.Fatalf("worst case %d exceeds an eighth of the budget %d", worst, tc.in.budget)
				}
			}
		})
	}
}

// The descriptor allowance is a hard cap: no floor rises above it,
// because a connection the kernel refuses with EMFILE is worse than one
// the server never admitted.
func TestDescriptorLimitIsAHardCap(t *testing.T) {
	p := computeResourcePlan(planInputs{budget: 32 * gib, cpus: 8, streamEngines: 2, fd: 512, sockets: 4})
	// What is already spoken for comes off the top: the reserve, the UDP
	// sockets, one accept descriptor per engine. Dividing fd-reserve
	// alone promised the UDP sockets' descriptors twice.
	perEngine := (512 - fdReserve - p.udpSockets - 2) / 2
	if p.tcpConns != perEngine {
		t.Fatalf("conns = %d, want the descriptor bound %d", p.tcpConns, perEngine)
	}
	if p.tcpConnsFD != perEngine {
		t.Fatalf("tcpConnsFD = %d, want %d", p.tcpConnsFD, perEngine)
	}
	if total := p.udpSockets + 2*p.tcpConns + fdReserve + 2; total > 512 {
		t.Fatalf("aggregate descriptor promise %d exceeds RLIMIT_NOFILE 512", total)
	}

	// An unlimited rlimit is no bound at all. Pushed through an int
	// conversion it wrapped negative, and a single-engine plan on an
	// unlimited host derived one connection.
	unlimited := computeResourcePlan(planInputs{budget: 32 * gib, cpus: 8, streamEngines: 1, fd: ^uint64(0), sockets: 4})
	unbounded := computeResourcePlan(planInputs{budget: 32 * gib, cpus: 8, streamEngines: 1, fd: 0, sockets: 4})
	if unlimited.tcpConns != unbounded.tcpConns {
		t.Fatalf("conns = %d under an unlimited rlimit, want the memory-derived %d",
			unlimited.tcpConns, unbounded.tcpConns)
	}
	if unbounded.tcpConnsFD != 0 {
		t.Fatalf("tcpConnsFD = %d with no descriptor bound, want 0", unbounded.tcpConnsFD)
	}

	// Two usable descriptors across two engines: one connection each,
	// and every job class shrinks with it. The old floor pushed this to
	// 16 connections a side and let the kernel break the promise.
	p = computeResourcePlan(planInputs{budget: 32 * gib, cpus: 8, streamEngines: 2, fd: fdReserve + 2, sockets: 4})
	if p.tcpConns != 1 {
		t.Fatalf("conns = %d with 2 usable descriptors, want 1", p.tcpConns)
	}
	if p.tcpSmallJobs != 1 || p.tcpLargeJobs != 1 {
		t.Fatalf("job classes small=%d large=%d for a single-connection engine, want 1/1",
			p.tcpSmallJobs, p.tcpLargeJobs)
	}

	// An allowance at or below the reserve is the severest case, not an
	// exemption: the cap check used to be inside `fd > reserve`, so a
	// ulimit of 64 skipped it entirely and kept the memory-derived
	// thousands.
	for _, fd := range []uint64{1, 64, fdReserve} {
		p = computeResourcePlan(planInputs{budget: 32 * gib, cpus: 8, streamEngines: 2, fd: fd, sockets: 4})
		if p.tcpConns != 1 {
			t.Fatalf("conns = %d with RLIMIT_NOFILE=%d, want 1", p.tcpConns, fd)
		}
	}

	// An explicit operator cap overrides the memory heuristics, never
	// the descriptor allowance: the configured value used to replace the
	// plan's limit entirely.
	clampPlan := computeResourcePlan(planInputs{budget: 32 * gib, cpus: 8, streamEngines: 2, fd: 512, sockets: 4})
	if e := newTCPEngine(echoHandler(), "tcp", 100000, clampPlan); e.maxConns != int64(clampPlan.tcpConnsFD) {
		t.Fatalf("explicit cap 100000 admitted %d conns, want the descriptor allowance %d",
			e.maxConns, clampPlan.tcpConnsFD)
	}
	if e := newTCPEngine(echoHandler(), "tcp", 10, clampPlan); e.maxConns != 10 {
		t.Fatalf("explicit cap 10 became %d, the operator's lower choice must stand", e.maxConns)
	}

	// The socket fan-out is descriptors too: sixteen reuseport sockets
	// under a ulimit of sixteen is a bind-time EMFILE, although one
	// socket and one listener would have fit comfortably.
	p = computeResourcePlan(planInputs{budget: 32 * gib, cpus: 32, streamEngines: 1, fd: 16, sockets: 16})
	if p.udpSockets > 2 {
		t.Fatalf("sockets = %d with RLIMIT_NOFILE=16, want the fan-out bound by descriptors", p.udpSockets)
	}
	if p.udpSockets < 1 {
		t.Fatalf("sockets = %d, a server needs one", p.udpSockets)
	}
}

// Two Servers in one process each live inside their own plan. The plan
// used to be a package global, and a probe against two servers read one
// server's connection cap from the other's arithmetic.
func TestPlanIsServerLocal(t *testing.T) {
	small := defaultResourcePlan(1)
	small.udpSpareSlabs = 4
	small.tcpConns = 3
	small.tcpSmallJobs = 3
	small.tcpLargeJobs = 1
	big := defaultResourcePlan(1)
	big.udpSpareSlabs = 4096
	big.tcpConns = 300
	big.tcpSmallJobs = 300
	big.tcpLargeJobs = 8

	eSmall := newTCPEngine(echoHandler(), "tcp", 0, small)
	eBig := newTCPEngine(echoHandler(), "tcp", 0, big)
	if cap(eSmall.smallTokens) != 3 || cap(eBig.smallTokens) != 300 {
		t.Fatalf("token caps %d/%d, want 3/300. The engines are reading a shared plan",
			cap(eSmall.smallTokens), cap(eBig.smallTokens))
	}
	if eSmall.maxConns != 3 || eBig.maxConns != 300 {
		t.Fatalf("conn caps %d/%d, want 3/300", eSmall.maxConns, eBig.maxConns)
	}

	uSmall := newUDPEngine(echoHandler(), nil, false, 1, 1, small)
	uBig := newUDPEngine(echoHandler(), nil, false, 1, 1, big)
	if uSmall.slabCap >= uBig.slabCap {
		t.Fatalf("slab caps %d/%d, want the small server's below the big one's",
			uSmall.slabCap, uBig.slabCap)
	}
}

// However strange the inputs, every bound stays inside sane limits: a
// server with no room is still a server, and a machine that reports
// something absurd does not get an absurd bound.
func TestResourcePlanStaysWithinLimits(t *testing.T) {
	budgets := []uint64{0, 1, 4 << 10, 64 * mib, 1 << 40, ^uint64(0)}
	cpuCounts := []int{0, 1, 4, 128}
	for _, budget := range budgets {
		for _, cpus := range cpuCounts {
			for _, engines := range []int{0, 1, 2} {
				for _, fd := range []uint64{0, 64, 1 << 20} {
					p := computeResourcePlan(planInputs{budget: budget, cpus: cpus, streamEngines: engines, fd: fd, sockets: 16})
					if p.udpSpareSlabs < 1 || p.udpSpareSlabs > maxSpareSlabs {
						t.Fatalf("budget %d: spare slabs %d", budget, p.udpSpareSlabs)
					}
					if p.tcpConns < 1 || p.tcpConns > maxTCPConns {
						t.Fatalf("budget %d fd %d: conns %d", budget, fd, p.tcpConns)
					}
					if p.udpWorkers < 64 || p.udpWorkers > 1024 {
						t.Fatalf("budget %d cpus %d: workers %d", budget, cpus, p.udpWorkers)
					}
					if p.tcpSmallJobs < 1 || p.tcpSmallJobs > maxSmallJobs {
						t.Fatalf("small jobs %d", p.tcpSmallJobs)
					}
					if p.tcpLargeJobs < 1 {
						t.Fatalf("large jobs %d", p.tcpLargeJobs)
					}
					if p.udpSockets < 1 || p.udpSockets > 16 {
						t.Fatalf("sockets %d", p.udpSockets)
					}
				}
			}
		}
	}
}

// What this machine decided, for the record: a failure here is a machine
// the derivation has not been thought about on, not a broken build.
func TestResourcePlanOnThisMachine(t *testing.T) {
	p := defaultResourcePlan(1)
	t.Logf("memory budget %d bytes -> sockets=%d workers=%d spare=%d conns=%d small=%d large=%d worst=%.1fMiB",
		memoryBudget(), p.udpSockets, p.udpWorkers, p.udpSpareSlabs, p.tcpConns,
		p.tcpSmallJobs, p.tcpLargeJobs, float64(p.worstCaseBytes(1))/mib)
	if p.udpSpareSlabs < 1 || p.udpSpareSlabs > maxSpareSlabs {
		t.Fatalf("spare bound %d", p.udpSpareSlabs)
	}
	if p.tcpConns < 1 || p.tcpConns > maxTCPConns {
		t.Fatalf("connection bound %d", p.tcpConns)
	}
}
