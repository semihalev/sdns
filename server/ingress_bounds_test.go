package server

import (
	"testing"
)

// The plan is derived because the machines differ. This checks the curve
// at both ends — the router the author never saw and the server the
// numbers were originally measured on — rather than the one value this
// build happens to compute here.
func TestResourcePlanFollowsTheMachine(t *testing.T) {
	const (
		mib = 1 << 20
		gib = 1 << 30
	)
	cases := []struct {
		name string
		in   planInputs

		workersAtMost, workersAtLeast int
		spareAtMost, spareAtLeast     int64
		connsAtMost, connsAtLeast     int
		largeJobs                     int
	}{
		{
			name: "128MB router, 4 cores",
			in:   planInputs{budget: 128 * mib, cpus: 4, streamEngines: 2},
			// The front door has to leave a 128MB device a resolver:
			// modest workers, a few hundred slabs, tens of connections.
			workersAtLeast: 64, workersAtMost: 64,
			spareAtLeast: minSpareSlabs, spareAtMost: 512,
			connsAtLeast: minTCPConns, connsAtMost: 256,
			largeJobs: defaultTCPLargeJobs / 2,
		},
		{
			// The container case: the cgroup is small, the host is not.
			// The tier follows the memory, never the cores — measured on a
			// 32-core box, where a 128MB scope was otherwise given 512
			// workers and a slab cap to match.
			name:           "128MB cgroup on a 32-core host",
			in:             planInputs{budget: 128 * mib, cpus: 32, streamEngines: 1},
			workersAtLeast: 64, workersAtMost: 64,
			spareAtLeast: minSpareSlabs, spareAtMost: 512,
			connsAtLeast: minTCPConns, connsAtMost: 512,
			largeJobs: defaultTCPLargeJobs / 2,
		},
		{
			name:           "512MB appliance, 2 cores",
			in:             planInputs{budget: 512 * mib, cpus: 2, streamEngines: 1},
			workersAtLeast: 128, workersAtMost: 128,
			spareAtLeast: 512, spareAtMost: 2048,
			connsAtLeast: 256, connsAtMost: 1024,
			largeJobs: defaultTCPLargeJobs,
		},
		{
			name:           "32GB server, 32 cores",
			in:             planInputs{budget: 32 * gib, cpus: 32, streamEngines: 1},
			workersAtLeast: 512, workersAtMost: 512,
			spareAtLeast: maxSpareSlabs, spareAtMost: maxSpareSlabs,
			connsAtLeast: maxTCPConns, connsAtMost: maxTCPConns,
			largeJobs: defaultTCPLargeJobs,
		},
		{
			name:           "unknown platform is treated as modest",
			in:             planInputs{budget: 0, cpus: 8, streamEngines: 1},
			workersAtLeast: 128, workersAtMost: 128,
			spareAtLeast: 512, spareAtMost: 2048,
			connsAtLeast: 256, connsAtMost: 1024,
			largeJobs: defaultTCPLargeJobs,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := computeResourcePlan(tc.in)
			if p.udpWorkers < tc.workersAtLeast || p.udpWorkers > tc.workersAtMost {
				t.Fatalf("workers = %d, want within [%d,%d]", p.udpWorkers, tc.workersAtLeast, tc.workersAtMost)
			}
			if p.udpSpareSlabs < tc.spareAtLeast || p.udpSpareSlabs > tc.spareAtMost {
				t.Fatalf("spare slabs = %d, want within [%d,%d]", p.udpSpareSlabs, tc.spareAtLeast, tc.spareAtMost)
			}
			if p.tcpConns < tc.connsAtLeast || p.tcpConns > tc.connsAtMost {
				t.Fatalf("conns = %d, want within [%d,%d]", p.tcpConns, tc.connsAtLeast, tc.connsAtMost)
			}
			if p.tcpLargeJobs != tc.largeJobs {
				t.Fatalf("large jobs = %d, want %d", p.tcpLargeJobs, tc.largeJobs)
			}
			if p.udpQueue != defaultIngressQueue {
				t.Fatalf("queue = %d, want %d", p.udpQueue, defaultIngressQueue)
			}
		})
	}
}

// The stream engines share one budget: enabling DoT must halve what each
// engine assumes, not double what the process spends.
func TestStreamEnginesShareTheBudget(t *testing.T) {
	alone := computeResourcePlan(planInputs{budget: 4 << 30, cpus: 8, streamEngines: 1})
	shared := computeResourcePlan(planInputs{budget: 4 << 30, cpus: 8, streamEngines: 2})
	if shared.tcpConns >= alone.tcpConns {
		t.Fatalf("conns alone=%d, with DoT=%d; two engines each assuming the "+
			"full budget is the failure this input exists to prevent",
			alone.tcpConns, shared.tcpConns)
	}
}

// A connection is an open descriptor, so the descriptor allowance binds
// admission the same way memory does.
func TestDescriptorLimitBindsConnections(t *testing.T) {
	p := computeResourcePlan(planInputs{budget: 32 << 30, cpus: 8, streamEngines: 2, fd: 512})
	perEngine := (512 - fdReserve) / 2
	if p.tcpConns != perEngine {
		t.Fatalf("conns = %d, want the descriptor bound %d", p.tcpConns, perEngine)
	}
	// And a tiny allowance still leaves a server rather than nothing.
	p = computeResourcePlan(planInputs{budget: 32 << 30, cpus: 8, streamEngines: 2, fd: 160})
	if p.tcpConns < minTCPConns {
		t.Fatalf("conns = %d under a tiny fd limit, want at least %d", p.tcpConns, minTCPConns)
	}
}

// However strange the inputs, every bound stays inside its floor and
// ceiling: a server with no room is still a server, and a machine that
// reports something absurd does not get an absurd bound.
func TestResourcePlanStaysWithinLimits(t *testing.T) {
	budgets := []uint64{0, 1, 4 << 10, 64 << 20, 1 << 40, ^uint64(0)}
	cpuCounts := []int{0, 1, 4, 128}
	for _, budget := range budgets {
		for _, cpus := range cpuCounts {
			for _, engines := range []int{0, 1, 2} {
				p := computeResourcePlan(planInputs{budget: budget, cpus: cpus, streamEngines: engines})
				if p.udpSpareSlabs < minSpareSlabs || p.udpSpareSlabs > maxSpareSlabs {
					t.Fatalf("budget %d: spare slabs %d outside [%d,%d]", budget, p.udpSpareSlabs, minSpareSlabs, maxSpareSlabs)
				}
				if p.tcpConns < minTCPConns || p.tcpConns > maxTCPConns {
					t.Fatalf("budget %d: conns %d outside [%d,%d]", budget, p.tcpConns, minTCPConns, maxTCPConns)
				}
				if p.udpWorkers < 64 || p.udpWorkers > 1024 {
					t.Fatalf("budget %d cpus %d: workers %d outside [64,1024]", budget, cpus, p.udpWorkers)
				}
				if p.tcpSmallJobs < 64 || p.tcpSmallJobs > maxSmallJobs {
					t.Fatalf("small jobs %d outside [64,%d]", p.tcpSmallJobs, maxSmallJobs)
				}
				if p.tcpLargeJobs < 1 {
					t.Fatalf("large jobs %d", p.tcpLargeJobs)
				}
			}
		}
	}
}

// The worst case the bounds allow has to stay a fraction of what the
// process may use — that is the whole point of deriving them.
func TestIngressWorstCaseFitsTheBudget(t *testing.T) {
	for _, budget := range []uint64{128 << 20, 512 << 20, 2 << 30, 32 << 30} {
		p := computeResourcePlan(planInputs{budget: budget, cpus: 8, streamEngines: 2})
		worst := uint64(p.udpSpareSlabs)*udpSlabBytes + //nolint:gosec // clamped positives
			uint64(2*p.tcpConns)*tcpConnBytes //nolint:gosec // clamped positives
		if share := float64(worst) / float64(budget); share > 0.15 {
			t.Fatalf("on %d bytes the front door could reach %d bytes (%.0f%%); "+
				"the cache, the resolver and the runtime need the rest",
				budget, worst, share*100)
		}
	}
}

// What this machine decided, for the record: a failure here is a machine
// the derivation has not been thought about on, not a broken build.
func TestResourcePlanOnThisMachine(t *testing.T) {
	p := computeResourcePlan(autoPlanInputs(1))
	t.Logf("memory budget %d bytes -> workers=%d spare=%d conns=%d small=%d large=%d",
		memoryBudget(), p.udpWorkers, p.udpSpareSlabs, p.tcpConns, p.tcpSmallJobs, p.tcpLargeJobs)
	if p.udpSpareSlabs < minSpareSlabs || p.udpSpareSlabs > maxSpareSlabs {
		t.Fatalf("spare bound %d outside [%d,%d]", p.udpSpareSlabs, minSpareSlabs, maxSpareSlabs)
	}
	if p.tcpConns < minTCPConns || p.tcpConns > maxTCPConns {
		t.Fatalf("connection bound %d outside [%d,%d]", p.tcpConns, minTCPConns, maxTCPConns)
	}
}
