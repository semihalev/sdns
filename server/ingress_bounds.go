package server

import (
	"math"
	"runtime/debug"
)

// The front door's burst bounds — how far the UDP slab ring may stretch,
// and how many connections the stream engines admit — are not constants.
// They are the answer to "what can this machine afford", and that answer
// is different on a 32-core server and on a 128MB router. A number
// compiled in is a guess about hardware the author never saw: too small
// on the server it was meant to protect, and an out-of-memory kill on the
// device it was never considered for.
//
// So they are derived at startup from the memory the process is actually
// allowed to use — the machine's, a container's limit, or GOMEMLIMIT,
// whichever binds first — and clamped at both ends so neither extreme
// produces a nonsense server.

const (
	// ingressMemoryShare is the fraction of the memory budget one
	// ingress subsystem may reach under saturation. Two of them (the UDP
	// stretch and the stream connections) take a share each, so the front
	// door's worst case is an sixteenth of what the process may use —
	// leaving the cache, the resolver's in-flight work and the runtime
	// itself the rest, which is what a resolver actually spends memory
	// on.
	ingressMemoryShare = 32

	// udpSpareBytes is what one borrowed slab costs: the two 4KB buffers
	// plus the per-request state the slab carries, rounded up so the
	// bound errs towards fewer slabs rather than more.
	udpSpareBytes = 12 << 10
	// tcpConnBytes is what one admitted connection costs: its framing
	// buffers plus the goroutine that serves it.
	tcpConnBytes = tcpFillSize + tcpDrainSize + (8 << 10)

	// Floors, so a small machine still has a server rather than a
	// bottleneck, and ceilings, because past these the resolver's own
	// in-flight bound (MaxConcurrentQueries, 10000 by default) is what
	// the queries are waiting on, not the front door.
	minSpareSlabs = 256
	maxSpareSlabs = 8192
	minTCPConns   = 128
	maxTCPConns   = 4096

	// unknownMemoryBudget is used where the platform will not say how
	// much memory it has. Deliberately modest: guessing high on an
	// unknown machine is the failure this whole file exists to avoid.
	unknownMemoryBudget = 512 << 20
)

// spareSlabBound is how far the UDP ring may stretch on this machine.
var spareSlabBound = int64(boundFor(memoryBudget(), udpSpareBytes, minSpareSlabs, maxSpareSlabs))

// tcpConnBound is how many connections a stream engine admits when the
// configuration is silent.
func tcpConnBound() int {
	return boundFor(memoryBudget(), tcpConnBytes, minTCPConns, maxTCPConns)
}

// boundFor divides one subsystem's share of budget into items of
// itemBytes, clamped. Pure, so the curve it produces can be checked
// against machines this build will never run on.
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
