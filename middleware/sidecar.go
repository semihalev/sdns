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

// WireHitGate judges record-bearing byte serves. When a gate is wired,
// the cache consults it before serving stored bytes for an exact hit or
// a composed CNAME chase; a false verdict declines the byte serve and the
// same query is answered by the decoded path instead — where the policy
// layer's own response writer sees a full message. Composite denial
// classes (subtree cuts, failure state) carry no stored records and are
// never gated.
//
// The gate owns any per-hit accounting: a true verdict is the only place
// a byte-served hit's policy outcome can be counted, because no later
// layer decodes it. Verdicts must be computed from the sidecars alone —
// per-query policy state belongs to the policy middleware's own
// query-time hold, which steers queries off the byte path entirely by
// withholding its writer's wire capability.
type WireHitGate interface {
	// AllowWireHit judges a single-entry byte serve. sc is the entry's
	// sidecar; nil means unevaluated.
	AllowWireHit(sc *Sidecar) bool
	// AllowWireChase judges a composed chase, one sidecar per segment in
	// chain order. Any nil element is an unevaluated segment.
	AllowWireChase(sidecars []*Sidecar) bool
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
