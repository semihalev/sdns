package middleware

import "github.com/miekg/dns"

// Sidecar is policy state stamped beside a cache entry: an opaque value a
// policy middleware computed from the entry's own stored records. The
// cache carries and hands it back without reading Value.
//
// The nil pointer is load-bearing: an absent sidecar means the entry was
// never evaluated — unknown, never clean. A policy layer that evaluated an
// entry and matched nothing must say so with a non-nil Sidecar, or every
// hit on that entry re-takes the decoded path forever.
type Sidecar struct {
	Value any
}

// SidecarEvaluator computes a Sidecar from one entry's stored message —
// the truth being admitted, after cacheability filtering, never the
// client's copy. It is called once per admitted entry through every
// admission door the store has. A nil result declines to evaluate and
// leaves the entry unknown.
//
// The evaluator runs on admission paths (resolver completions, prefetch
// refreshes, the cache writer) and must be safe for concurrent use.
type SidecarEvaluator func(msg *dns.Msg) *Sidecar

// WireHitVerdict is a gate's judgment of one byte serve.
type WireHitVerdict uint8

const (
	// WireHitServe permits the byte serve. Nothing is counted here — a
	// serve can still decline past the gate (writer readiness, build,
	// transport fallback) and land on the decoded path, so accounting
	// waits for the committed-bytes callback below.
	WireHitServe WireHitVerdict = iota
	// WireHitDecode sends the query to the decoded path because policy
	// wants the full message there. The sidecar itself was usable; the
	// cache changes nothing about it.
	WireHitDecode
	// WireHitRestamp sends the query to the decoded path because the
	// sidecar is unusable — unevaluated, or stamped under a generation
	// the gate no longer accepts. The decoded serve re-evaluates the
	// entry's records and restamps over the judged pointer, so the entry
	// rejoins the byte path instead of decoding until eviction.
	WireHitRestamp
)

// SidecarChainCap bounds a chase composition's segments; it mirrors the
// wire chase depth (the cache asserts its own bound fits at compile
// time).
const SidecarChainCap = 10

// SidecarChain carries one sidecar per chase segment, in chain order, as
// a bounded value — never a slice. The gate methods receive it by value,
// so a gated chase hit stays allocation-free: a slice here escapes
// through the interface call and puts a heap allocation on every
// cache-contained chase, which the zero-allocation hit contract forbids.
type SidecarChain struct {
	n   int
	scs [SidecarChainCap]*Sidecar
}

// Append adds the next segment's sidecar; it reports false when the
// chain is full (the caller's depth bound should make that impossible).
func (c *SidecarChain) Append(sc *Sidecar) bool {
	if c.n >= len(c.scs) {
		return false
	}
	c.scs[c.n] = sc
	c.n++
	return true
}

// Len returns the number of segments carried.
func (c *SidecarChain) Len() int { return c.n }

// At returns segment i's sidecar; nil means that segment is unevaluated.
func (c *SidecarChain) At(i int) *Sidecar { return c.scs[i] }

// WireHitGate judges record-bearing byte serves. When a gate is wired,
// the cache consults it before serving stored bytes for an exact hit or
// a composed CNAME chase; any verdict but WireHitServe declines the byte
// serve and the same query is answered by the decoded path instead —
// where the policy layer's own response writer sees a full message.
// Composite denial classes (subtree cuts, failure state) carry no stored
// records and are never gated.
//
// The Judge methods are deterministic decisions over the sidecars and —
// for a per-query gate obtained through QueryPolicyGate — that query's
// own policy state. A per-query gate may memoize the decision it judged;
// the matching Count method then records exactly that decision, which is
// what keeps a judge/commit pair coherent across a concurrent policy
// reload. Accounting fires exactly once per byte-served hit, after the
// bytes were committed to the transport — the only point where a byte
// serve can no longer fall back to the decoded path and be counted
// twice. Queries whose policy work must all happen on the decoded path
// are steered off the byte path by the policy writer withholding its
// wire capability.
type WireHitGate interface {
	// JudgeWireHit judges a single-entry byte serve. sc is the entry's
	// sidecar; nil means unevaluated.
	JudgeWireHit(sc *Sidecar) WireHitVerdict
	// JudgeWireChase judges a composed chase, one sidecar per segment in
	// chain order. Any nil element is an unevaluated segment.
	JudgeWireChase(sidecars SidecarChain) WireHitVerdict
	// CountWireHit records the policy outcome of a byte-served exact
	// hit. Called once, after the transport accepted the bytes; no later
	// layer decodes them, so this is the only place the outcome exists.
	CountWireHit(sc *Sidecar)
	// CountWireChase is CountWireHit for a committed chase composition.
	CountWireChase(sidecars SidecarChain)
}

// QueryPolicyGate is implemented by a policy middleware's response
// writer to carry this query's own gate — the channel through which
// query-time state (held candidates, a decision that already fell, an
// exemption) reaches the byte-serve judgment. When the writer offers
// one, the cache consults it instead of the globally wired gate, judge
// and count alike, for the whole hit. A nil return falls back to the
// global gate.
type QueryPolicyGate interface {
	QueryWireHitGate() WireHitGate
}

// SidecarPolicyProvider is implemented by the handler that owns response
// policy over stored answers (tomorrow: rpz). Either method may return
// nil to leave that half of the seam unwired.
type SidecarPolicyProvider interface {
	SidecarEvaluator() SidecarEvaluator
	WireHitGate() WireHitGate
}

// SidecarPolicySetter is implemented by the handler that owns the entry
// store (today: the cache middleware). Setup wires the first provider in
// pipeline order into every setter.
type SidecarPolicySetter interface {
	SetSidecarPolicy(p SidecarPolicyProvider)
}
