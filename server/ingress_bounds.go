package server

import (
	"math"
	"runtime"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
)

// The front door's bounds, how many queries may hold a slab at once,
// how many connections the stream engines admit, how many workers and
// sockets serve, are not constants. They are the answer to "what can
// this machine afford", and that answer is different on a 32-core
// server and on a 128MB router. A number compiled in is a guess about
// hardware the author never saw: too small on the server it was meant
// to protect, and an out-of-memory kill on the device it was never
// considered for.
//
// So one plan is derived per Server from what the process actually has:
// the memory it may use (the machine's, a container's limit, or
// GOMEMLIMIT, whichever binds first), its CPUs, its file-descriptor
// allowance, and which listeners are enabled, the stream engines share
// one stream budget rather than each assuming it is alone. The plan is
// a value handed down through the listeners to the engines: no global,
// so two Servers in one process each live inside their own arithmetic.
//
// The budget is charged what the bounds can actually cost. Every slab
// class is priced at its real allocator size, the UDP job, the TCP
// small pair, the 128KB large pair, the connection's stream state, and
// a bound is shrunk until its worst case fits its share. The floors can
// still win on a very small budget, because a server with no room has
// to be a server before it is a small one; the accounting test states
// how far past the share the floors may reach.
//
// The bounds are admission caps, not reservations: nothing here is
// allocated up front. Slabs are created on demand, retained in an
// explicit idle cache up to the cap, and released by trim (see
// slab_cache.go), so a device's resident memory follows its own
// traffic rather than this file's arithmetic.

const (
	// ingressMemoryShare is the fraction of the memory budget one
	// ingress subsystem may reach under saturation. Two of them (the UDP
	// slabs and the stream engines) take a share each, so the front
	// door's worst case is a sixteenth of what the process may use,
	// leaving the cache, the resolver's in-flight work and the runtime
	// itself the rest, which is what a resolver actually spends memory
	// on.
	ingressMemoryShare = 32

	// The real costs, at allocator size-class granularity, rounded up so
	// the arithmetic errs towards fewer items rather than more.
	//
	// udpSlabBytes: the udpJob lands in the 9,472B class; state and cache
	// bookkeeping ride along.
	udpSlabBytes = 12 << 10
	// tcpSmallJobBytes: 2KB RX class + 16,384B TX class + job state.
	tcpSmallJobBytes = 20 << 10
	// tcpLargeJobBytes: two protocol-maximum buffers.
	tcpLargeJobBytes = 132 << 10
	// tcpConnBytes: the connection's stream (fill + drain buffers land in
	// the 13,568B class) plus the goroutine that serves it.
	tcpConnBytes = 24 << 10

	// Ceilings, because past these the resolver's own in-flight bound
	// (MaxConcurrentQueries, 10000 by default) is what queries wait on,
	// not the front door.
	maxSpareSlabs = 8192
	maxTCPConns   = 4096

	// fdReserve is what the rest of the process needs open, upstream
	// sockets, the API listener, log and database files, before
	// connections may have the remainder. The descriptor cap is a hard
	// cap: no floor rises above it, because a connection the kernel
	// refuses with EMFILE is worse than one the server never admitted.
	fdReserve = 128

	// unknownMemoryBudget is used where the platform will not say how
	// much memory it has. Deliberately modest: guessing high on an
	// unknown machine is the failure this whole file exists to avoid.
	unknownMemoryBudget = 512 << 20
)

// ingressPlanGauge publishes the derived bounds where an operator can
// read them at any time. The startup log line carries the same numbers,
// but it lands in the middle of the startup burst, measured on a
// canary, journald's throttle dropped exactly that line, and a bound
// nobody can observe might as well be a constant. One process, one
// plan: with several Servers in a process the last one published wins,
// which the metric help states.
var ingressPlanGauge = func() *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_ingress_plan",
		Help: "Derived serving bounds for this process (last Server started wins)",
	}, []string{"bound"})
	prometheus.MustRegister(g)
	return g
}()

// publish exposes the plan's decisions as gauges.
func (p resourcePlan) publish() {
	set := func(bound string, v int64) {
		ingressPlanGauge.WithLabelValues(bound).Set(float64(v))
	}
	set("udp_sockets", int64(p.udpSockets))
	set("udp_workers", int64(p.udpWorkers))
	set("udp_queue", int64(p.udpQueue))
	set("udp_spare_slabs", p.udpSpareSlabs)
	set("tcp_conns", int64(p.tcpConns))
	set("tcp_small_jobs", int64(p.tcpSmallJobs))
	set("tcp_large_jobs", int64(p.tcpLargeJobs))
}

// resourcePlan is the one set of derived bounds a Server's engines read.
// It is plain data, computed once in New and passed by value.
type resourcePlan struct {
	udpSockets    int
	udpWorkers    int
	udpQueue      int
	udpSpareSlabs int64

	tcpConns     int
	tcpSmallJobs int
	tcpLargeJobs int
	// tcpConnsFD is the descriptor-derived half of the connection cap on
	// its own (0 when no descriptor bound applies). An explicit operator
	// cap may override the memory heuristics but never this: admission
	// past it is EMFILE at accept.
	tcpConnsFD int
}

type planInputs struct {
	budget        uint64
	cpus          int
	streamEngines int
	fd            uint64
	// sockets is the platform's UDP fan-out before the memory tier has
	// its say (reuseport_*.go).
	sockets int
}

// defaultResourcePlan derives the plan for this process and this many
// stream engines.
func defaultResourcePlan(streamEngines int) resourcePlan {
	return computeResourcePlan(planInputs{
		budget:        memoryBudget(),
		cpus:          runtime.GOMAXPROCS(0),
		streamEngines: streamEngines,
		fd:            fdSoftLimit(),
		sockets:       defaultUDPWorkers(),
	})
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

	// Tier floors. A very small budget gets small floors: a floor is
	// there so a device still has a server, not so the arithmetic can
	// spend memory the device does not have.
	lowTier := budget < 256<<20
	spareFloor := int64(256)
	smallFloor, connsFloor := 64, 16
	if lowTier {
		spareFloor, smallFloor, connsFloor = 64, 32, 8
	}

	// Workers are concurrency, not CPUs: a worker runs the chain inline
	// and a miss holds one for the length of an upstream resolution. On
	// the low-memory tiers the count is fixed rather than CPU-scaled, a
	// container on a many-core host still gets the pool its memory can
	// carry, because every worker is a stack and a slot in the slab cap,
	// and the overflow path keeps miss concurrency unbounded either way.
	var workers int
	switch {
	case lowTier:
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

	// Socket fan-out follows the same logic: each reader can hold a
	// batch of slabs, so sockets are slots in the slab cap too, and a
	// small budget throttles throughput long before fan-out does. The
	// descriptor allowance binds here as well. Every socket is an open
	// descriptor, and a fan-out the kernel answers with EMFILE at bind
	// is a listener that never comes up at all.
	sockets := in.sockets
	if sockets < 1 {
		sockets = 1
	}
	if lowTier && sockets > 4 {
		sockets = 4
	}
	if in.fd > 0 {
		if fdCap := int(in.fd / 8); sockets > fdCap { //nolint:gosec // bounded small
			sockets = fdCap
		}
		if sockets < 1 {
			sockets = 1
		}
	}

	// UDP: the steady state (queue + workers + a reader's arming reserve
	// per socket) is charged first; the burst headroom gets what is left
	// of the share, floored so a burst is always worth admitting and
	// capped where the resolver's own bound takes over.
	queue := defaultIngressQueue
	steady := int64(queue + workers + sockets*udpReaderReserve)
	allowance := int64(budget / ingressMemoryShare) //nolint:gosec // budget is bounded by real memory sizes
	spare := allowance/udpSlabBytes - steady
	if spare < spareFloor {
		spare = spareFloor
	}
	if spare > maxSpareSlabs {
		spare = maxSpareSlabs
	}

	// Streams: one share, split across the engines, charged at real
	// cost. The large class is priced first because it is the expensive
	// one; connections and the small class share the rest, and a
	// connection is only admissible with a small slab to serve it, so
	// they are priced together.
	streamAllowance := allowance / int64(engines)
	// The large class follows the same tiers as the workers: its slabs
	// are the expensive ones, and a mid-sized machine does not need the
	// full complement of 128KB pairs to serve the rare frames they exist
	// for.
	largeJobs := defaultTCPLargeJobs
	switch {
	case lowTier:
		largeJobs = 4
	case budget < 1<<30:
		largeJobs = defaultTCPLargeJobs / 2
	}
	if int64(largeJobs)*tcpLargeJobBytes > streamAllowance/2 {
		largeJobs = int(streamAllowance / 2 / tcpLargeJobBytes)
		if largeJobs < 1 {
			largeJobs = 1
		}
	}
	connRoom := streamAllowance - int64(largeJobs)*tcpLargeJobBytes
	conns := int(connRoom / (tcpConnBytes + tcpSmallJobBytes))
	if conns > maxSmallJobs {
		// Past the small-class ceiling an extra connection costs only
		// itself.
		conns = maxSmallJobs + int((connRoom-int64(maxSmallJobs)*(tcpConnBytes+tcpSmallJobBytes))/tcpConnBytes)
	}
	if conns < connsFloor {
		conns = connsFloor
	}
	if conns > maxTCPConns {
		conns = maxTCPConns
	}

	// The descriptor allowance is a hard cap, applied after every floor:
	// admission above it is a promise the kernel will break with EMFILE.
	// What is already spoken for, the reserve, the UDP sockets, one
	// accept descriptor per stream engine, comes off the top first, so
	// the same descriptor is never promised twice; an allowance at or
	// below that is the severest case, not an exemption, and each engine
	// gets one connection. The arithmetic stays in uint64 until the
	// ceiling brings it into range: an unlimited rlimit pushed through an
	// int conversion wraps negative, and this cap once read that as "one
	// connection per engine".
	fdConnCap := 0
	if in.fd > 0 {
		fdCap := uint64(1)
		fixed := uint64(fdReserve) + uint64(sockets) + uint64(engines) //nolint:gosec // small positive counts
		if in.fd > fixed {
			usable := (in.fd - fixed) / uint64(engines) //nolint:gosec // engines >= 1
			if usable > maxTCPConns {
				usable = maxTCPConns
			}
			if usable > 1 {
				fdCap = usable
			}
		}
		fdConnCap = int(fdCap) //nolint:gosec // capped at maxTCPConns above
		if conns > fdConnCap {
			conns = fdConnCap
		}
	}

	smallJobs := conns
	if smallJobs < smallFloor {
		smallJobs = smallFloor
	}
	if smallJobs > maxSmallJobs {
		smallJobs = maxSmallJobs
	}
	// But never more small slabs than admissible connections: a server
	// cannot have more frames in flight than clients to send them.
	if smallJobs > conns {
		smallJobs = conns
	}
	if largeJobs > conns {
		largeJobs = conns
	}
	if largeJobs < 1 {
		largeJobs = 1
	}
	if smallJobs < 1 {
		smallJobs = 1
	}

	return resourcePlan{
		udpSockets:    sockets,
		udpWorkers:    workers,
		udpQueue:      queue,
		udpSpareSlabs: spare,
		tcpConns:      conns,
		tcpSmallJobs:  smallJobs,
		tcpLargeJobs:  largeJobs,
		tcpConnsFD:    fdConnCap,
	}
}

// worstCaseBytes is what this plan can cost at full saturation, priced
// at real allocator sizes. It exists for the accounting test: the
// arithmetic above must keep this inside the front door's share, floors
// aside.
func (p resourcePlan) worstCaseBytes(streamEngines int) int64 {
	if streamEngines < 1 {
		streamEngines = 1
	}
	udp := int64(p.udpQueue+p.udpWorkers+p.udpSockets*udpReaderReserve) + p.udpSpareSlabs
	stream := int64(p.tcpConns)*tcpConnBytes +
		int64(p.tcpSmallJobs)*tcpSmallJobBytes +
		int64(p.tcpLargeJobs)*tcpLargeJobBytes
	return udp*udpSlabBytes + int64(streamEngines)*stream
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
