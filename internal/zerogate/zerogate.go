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

// The gate returns two verdicts, and neither of them is a budget for
// allocating while serving.
//
// The first is exact and carries the claim: with every allocation
// profiled, no object may be allocated on a goroutine that is serving a
// query. Attribution by stack is what makes an exact zero meaningful —
// a process-wide counter cannot tell a query's allocation from a
// timer's, so it can only ever be compared against slack, and slack is
// how "0.05/op" once let fifty thousand allocations per million queries
// read as zero.
//
// The second covers what attribution cannot see: work a serving
// goroutine hands to another goroutine, which allocates under a stack
// with no engine frame on it. Two windows are measured, the second
// carrying twice the traffic of the first. Constant background — metric
// flushers, timers, the runtime — is the same in both and cancels in the
// difference, so what survives is per-query. ScalingSlack bounds that
// difference; it is not an allowance per query but the jitter between
// two windows, and it divides by the operation count, so at a million
// queries it holds the per-query cost below one ten-thousandth of an
// object.
const ScalingSlack = 64
