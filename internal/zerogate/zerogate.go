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

// Stage names the currently active budget row. It moves forward as stages
// land; budgets only ever tighten.
const Stage = "G0"

// PerOpBudget is the per-operation malloc ceiling for the active stage, by
// flavor. G0 measures the miekg-based server as it stands — the ceiling is
// a regression tripwire, not a target. S1a replaces the server layer,
// Z1 removes the request decode and context, Z2b pins zero (delta == 0,
// not a rounded per-op figure).
var PerOpBudget = map[string]map[string]float64{
	"G0": {
		FlavorUDP4Specific: 100,
		FlavorTCP:          130,
	},
}

// Budget returns the active ceiling for flavor, and whether the flavor is
// gated at the active stage at all.
func Budget(flavor string) (float64, bool) {
	stage, ok := PerOpBudget[Stage]
	if !ok {
		return 0, false
	}
	b, ok := stage[flavor]
	return b, ok
}
