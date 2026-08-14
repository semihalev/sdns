// Package zerogate defines the hard-zero allocation gate: a real SDNS
// server runs as a subprocess (allocation counters are process-global) with
// the named default middleware chain, a loopback authority, and a fully
// silent control plane; the parent process drives a hit-only corpus through
// a transport flavor and asserts the server's malloc delta over the
// measurement window against the active stage's budget.
//
// The envelope is the full job lifecycle: the window opens before the
// receive wrapper is entered and closes after the send wrapper returns —
// measured process-wide between two marks, each taken after two forced
// garbage collections (the second empties sync.Pool victim caches), with
// every warmup completed and every reply accounted for. The end state must
// satisfy the accounting identity: replies == operations, with zero
// fallbacks, drops, and errors observed by the client.
//
// Budgets are per-stage: the G0 baseline records the library server's cost
// and trips on regression; stages tighten it until Z2b pins zero. The final
// claim is "hard zero Go heap-object allocation", scoped to linux/amd64 and
// the pinned toolchain in CI; other platforms run the same gate with
// functional expectations only.
package zerogate

import "fmt"

// Zone is the authority's zone; every corpus name lives directly under it.
const Zone = "zero.test."

// CorpusSize is how many distinct names the hit corpus carries. Small
// enough to warm quickly, large enough to spread cache buckets.
const CorpusSize = 64

// CorpusName returns the i-th corpus name.
func CorpusName(i int) string {
	return fmt.Sprintf("h%04d.%s", i%CorpusSize, Zone)
}

// Flavors the gate knows. Each lands with its stage; the parent skips
// flavors whose stage has not shipped.
const (
	FlavorUDP4Specific = "udp4-specific"
	FlavorUDP4Wildcard = "udp4-wildcard"
	FlavorUDP6Specific = "udp6-specific"
	FlavorUDP6Wildcard = "udp6-wildcard"
	FlavorTCP          = "tcp"
)

// Stage names the currently gated row. It moves forward as stages land;
// the set of gated flavors only ever grows.
const Stage = "Z1"

// gated lists the flavors whose served traffic must add no allocations.
var gated = map[string]map[string]bool{
	"Z1": {
		FlavorUDP4Specific: true,
		FlavorTCP:          true,
	},
}

// Gated reports whether flavor is gated at the active stage.
func Gated(flavor string) bool { return gated[Stage][flavor] }

// AmbientSlack is how far a traffic window may exceed an idle window of
// the same length before the gate calls it a regression.
//
// The verdict is deliberately not a per-operation budget. A per-op
// ceiling scales with the run: 0.05/op reads like zero and permits fifty
// thousand allocations over a million queries, which is how a served hit
// that allocated a Chain from a pool passed for "0.00/op". What is
// measured instead is the difference between a window carrying traffic
// and an idle window of the same duration — the process's own background
// work (metric flushers, timers, the runtime) cancels out, and what
// remains is what the queries cost. That number must be zero, up to the
// jitter between two such windows, which is what this constant is: an
// absolute count, independent of how many queries ran.
const AmbientSlack = 256
