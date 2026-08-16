package server

import (
	"math"
	"runtime"
	"runtime/debug"

	"github.com/semihalev/sdns/config"
)

// The front door's bounds — how many queries may hold a slab at once,
// how many connections the stream engines admit, how many workers serve
// — are not constants. They are the answer to "what can this machine
// afford", and that answer is different on a 32-core server and on a
// 128MB router. A number compiled in is a guess about hardware the
// author never saw: too small on the server it was meant to protect,
// and an out-of-memory kill on the device it was never considered for.
//
// So one plan is derived at startup from what the process actually has:
// the memory it may use (the machine's, a container's limit, or
// GOMEMLIMIT, whichever binds first), its CPUs, its file-descriptor
// allowance, and which listeners are enabled — the stream engines share
// one stream budget rather than each assuming it is alone. Every bound
// is clamped at both ends so neither extreme produces a nonsense
// server, and every decision is logged where the listener starts.
//
// The bounds are admission caps, not reservations: nothing here is
// allocated up front. Slabs are created on demand, retained in an
// explicit idle cache up to the cap, and released by trim (see
// slab_cache.go), so a device's resident memory follows its own
// traffic rather than this file's arithmetic.

const (
	// ingressMemoryShare is the fraction of the memory budget one
	// ingress subsystem may reach under saturation. Two of them (the UDP
	// slabs and the stream connections) take a share each, so the front
	// door's worst case is a sixteenth of what the process may use —
	// leaving the cache, the resolver's in-flight work and the runtime
	// itself the rest, which is what a resolver actually spends memory
	// on.
	ingressMemoryShare = 32

	// udpSlabBytes is what one leased slab costs: the two 4KB buffers
	// plus the per-request state it carries, rounded up so the bound
	// errs towards fewer slabs rather than more.
	udpSlabBytes = 12 << 10
	// tcpConnBytes is what one admitted connection costs: its framing
	// buffers plus the goroutine that serves it.
	tcpConnBytes = tcpFillSize + tcpDrainSize + (8 << 10)

	// Floors, so a small machine still has a server rather than a
	// bottleneck, and ceilings, because past these the resolver's own
	// in-flight bound (MaxConcurrentQueries, 10000 by default) is what
	// the queries are waiting on, not the front door.
	minSpareSlabs = 256
	maxSpareSlabs = 8192
	minTCPConns   = 16
	maxTCPConns   = 4096

	// fdReserve is what the rest of the process needs open — upstream
	// sockets, the API listener, log and database files — before
	// connections may have the remainder.
	fdReserve = 128

	// unknownMemoryBudget is used where the platform will not say how
	// much memory it has. Deliberately modest: guessing high on an
	// unknown machine is the failure this whole file exists to avoid.
	unknownMemoryBudget = 512 << 20
)

// resourcePlan is the one set of derived bounds every engine reads.
type resourcePlan struct {
	udpWorkers int
	udpQueue   int
	// udpSpareSlabs is the admission headroom beyond the steady-state
	// formula (queue + workers + a batch per reader): how many extra
	// queries may hold a slab during a miss-heavy burst.
	udpSpareSlabs int64

	tcpConns     int
	tcpSmallJobs int
	tcpLargeJobs int
}

type planInputs struct {
	budget        uint64
	cpus          int
	streamEngines int
	fd            uint64
}

// activePlan is what engines read when their configuration is silent.
// Server.New replaces it (configureResourcePlan) before any listener
// exists; the init value serves engines constructed directly in tests.
var activePlan = computeResourcePlan(autoPlanInputs(1))

func autoPlanInputs(streamEngines int) planInputs {
	return planInputs{
		budget:        memoryBudget(),
		cpus:          runtime.GOMAXPROCS(0),
		streamEngines: streamEngines,
		fd:            fdSoftLimit(),
	}
}

// configureResourcePlan derives the plan for this configuration. Called
// once, before the listeners are built.
func configureResourcePlan(cfg *config.Config) {
	engines := 1
	if cfg.BindTLS != "" {
		engines = 2
	}
	activePlan = computeResourcePlan(autoPlanInputs(engines))
}

// computeResourcePlan is pure, so the curve it produces can be checked
// against machines this build will never run on.
func computeResourcePlan(in planInputs) resourcePlan {
	budget := in.budget
	if budget == 0 {
		budget = unknownMemoryBudget
	}
	engines := in.streamEngines
	if engines < 1 {
		engines = 1
	}

	// Workers are concurrency, not CPUs: a worker runs the chain inline
	// and a miss holds one for the length of an upstream resolution, so
	// the pool is sized for queries in flight. On the low-memory tiers
	// the count is fixed rather than CPU-scaled — a container on a
	// many-core host still gets the small pool its memory can carry,
	// because every worker is a stack and a slot in the slab cap, and
	// the overflow path keeps miss concurrency unbounded either way.
	var workers int
	switch {
	case budget < 256<<20:
		workers = 64
	case budget < 1<<30:
		workers = 128
	default:
		workers = in.cpus * 16
		if workers < 256 {
			workers = 256
		}
		if workers > 1024 {
			workers = 1024
		}
	}

	// Stream connections split one stream budget: with DoT enabled, TCP
	// and DoT each get half rather than each assuming it is alone. The
	// descriptor allowance binds the same way — a connection is a
	// descriptor held open.
	conns := boundFor(budget/uint64(engines), tcpConnBytes, minTCPConns, maxTCPConns) //nolint:gosec // engines >= 1
	if in.fd > fdReserve {
		if fdCap := (in.fd - fdReserve) / uint64(engines); uint64(conns) > fdCap { //nolint:gosec // conns is a clamped positive
			conns = int(fdCap) //nolint:gosec // below a positive int already
		}
	}
	if conns < minTCPConns {
		conns = minTCPConns
	}

	// Small jobs bound frames in flight, which connections bound already
	// — decoupled here so a large connection cap cannot inflate the slab
	// bound past its own ceiling, and a tiny one cannot starve it.
	smallJobs := conns
	if smallJobs < 64 {
		smallJobs = 64
	}
	if smallJobs > maxSmallJobs {
		smallJobs = maxSmallJobs
	}

	largeJobs := defaultTCPLargeJobs
	if budget < 512<<20 {
		largeJobs = defaultTCPLargeJobs / 2
	}

	return resourcePlan{
		udpWorkers:    workers,
		udpQueue:      defaultIngressQueue,
		udpSpareSlabs: int64(boundFor(budget, udpSlabBytes, minSpareSlabs, maxSpareSlabs)),
		tcpConns:      conns,
		tcpSmallJobs:  smallJobs,
		tcpLargeJobs:  largeJobs,
	}
}

// boundFor divides one subsystem's share of budget into items of
// itemBytes, clamped.
func boundFor(budget uint64, itemBytes, minItems, maxItems int) int {
	if itemBytes <= 0 || budget == 0 {
		budget = unknownMemoryBudget
	}
	n := budget / ingressMemoryShare / uint64(itemBytes) //nolint:gosec // itemBytes is a positive constant
	switch {
	case n < uint64(minItems): //nolint:gosec // minItems is a positive constant
		return minItems
	case n > uint64(maxItems): //nolint:gosec // maxItems is a positive constant
		return maxItems
	}
	return int(n) //nolint:gosec // clamped to maxItems above
}

// memoryBudget is how much memory this process may use: the machine's,
// narrowed by a container limit and by GOMEMLIMIT if either is smaller.
// Zero when nothing will say.
func memoryBudget() uint64 {
	budget := systemMemoryBytes()
	if limit := containerMemoryLimit(); limit > 0 && (budget == 0 || limit < budget) {
		budget = limit
	}
	// GOMEMLIMIT is the operator saying it out loud, so it wins whenever
	// it is set and tighter. SetMemoryLimit(-1) only reads.
	if limit := debug.SetMemoryLimit(-1); limit > 0 && limit != math.MaxInt64 {
		if budget == 0 || uint64(limit) < budget { //nolint:gosec // limit is positive here
			budget = uint64(limit)
		}
	}
	return budget
}
