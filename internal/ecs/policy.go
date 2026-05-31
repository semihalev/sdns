// Package ecs holds the policy and helpers for EDNS Client Subnet
// handling (RFC 7871). The package is deliberately tiny and free of
// DNS handlers, goroutines, or other side effects so middleware/edns
// (forwarding side) and middleware/cache (key-shape side) can both
// import it without bringing each other into their dependency graph.
//
// RFC 7871 is opt-in by design — SDNS strips ECS by default to
// honour §11's privacy guidance, and the operator must enable
// forwarding explicitly via the [ecs] config block.
package ecs

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// Policy captures the operator's decisions about how SDNS handles
// EDNS Client Subnet on inbound and outbound traffic. A nil *Policy
// represents the pre-7871 default: strip ECS on the way out, ignore
// SCOPE on the way back, do not key the cache on subnet. Methods on
// Policy tolerate a nil receiver, so the strip-only default doesn't
// need a sentinel.
type Policy struct {
	// Enabled toggles ECS forwarding upstream. When false every
	// other field is ignored. Default false (RFC 7871 §11).
	Enabled bool

	// ForwardV4Max / ForwardV6Max are the ceilings on the
	// source-prefix-length we'll forward upstream. Clients that
	// send a narrower (more specific) prefix get clamped to these
	// values — narrower prefixes leak more information about the
	// client than the operator probably intends. Sensible defaults:
	// /24 for IPv4 and /56 for IPv6, matching common practice.
	ForwardV4Max uint8
	ForwardV6Max uint8

	// ClientNetworks restricts which clients are eligible for ECS
	// forwarding. Empty == every client is eligible. A non-empty
	// list lets an operator forward ECS only for known internal
	// load balancers or CDN edges while stripping for the open
	// internet.
	ClientNetworks []netip.Prefix

	// MinScopeV4 / MinScopeV6 are the Stage-2 cache safety knobs:
	// when caching a scoped answer, refuse to key on a prefix
	// narrower than this. Caps cache cardinality so a busy
	// resolver with diverse clients can't blow up the cache
	// budget on per-client scopes. Defaults match the forwarding
	// ceilings.
	MinScopeV4 uint8
	MinScopeV6 uint8
}

// Build constructs a Policy from raw config primitives, returning
// (nil, nil) when the feature is disabled and (nil, error) on any
// malformed input. Callers (middleware/edns, middleware/cache) log
// the error context themselves. Keeping the constructor here keeps
// internal/ecs at the bottom of the dependency graph — no config
// import — while preventing two middleware from drifting on what
// "enabled" means.
//
// Bad input is fail-closed: a single typo'd CIDR or out-of-range
// source ceiling disables the entire policy. Forwarding off is
// always safer than forwarding too much.
func Build(
	enabled bool,
	forwardV4, forwardV6 uint8,
	minScopeV4, minScopeV6 uint8,
	clientNetworks []string,
) (*Policy, error) {
	if !enabled {
		return nil, nil
	}
	if forwardV4 == 0 {
		forwardV4 = 24
	}
	if forwardV4 > 32 {
		return nil, &policyError{field: "forward_v4", value: int(forwardV4), maxv: 32}
	}
	if forwardV6 == 0 {
		forwardV6 = 56
	}
	if forwardV6 > 128 {
		return nil, &policyError{field: "forward_v6", value: int(forwardV6), maxv: 128}
	}
	if minScopeV4 == 0 {
		minScopeV4 = forwardV4
	}
	if minScopeV4 > 32 {
		return nil, &policyError{field: "min_scope_v4", value: int(minScopeV4), maxv: 32}
	}
	if minScopeV6 == 0 {
		minScopeV6 = forwardV6
	}
	if minScopeV6 > 128 {
		return nil, &policyError{field: "min_scope_v6", value: int(minScopeV6), maxv: 128}
	}
	nets := make([]netip.Prefix, 0, len(clientNetworks))
	for _, s := range clientNetworks {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, &policyError{field: "client_networks", entry: s, cause: err}
		}
		nets = append(nets, p)
	}
	return &Policy{
		Enabled:        true,
		ForwardV4Max:   forwardV4,
		ForwardV6Max:   forwardV6,
		ClientNetworks: nets,
		MinScopeV4:     minScopeV4,
		MinScopeV6:     minScopeV6,
	}, nil
}

// policyError carries enough context for callers to log a
// human-meaningful "ECS disabled: <reason>" line without parsing
// the message back out.
type policyError struct {
	field string
	value int    // for numeric range failures
	maxv  int    // for numeric range failures
	entry string // for client_networks parse failures
	cause error  // underlying parse error, if any
}

func (e *policyError) Error() string {
	if e.cause != nil {
		return e.field + " entry " + e.entry + ": " + e.cause.Error()
	}
	return e.field + " out of range"
}

// Field, Value, Max, Entry, Cause expose the parts for structured
// logging without resorting to error message regex.
func (e *policyError) Field() string { return e.field }
func (e *policyError) Value() int    { return e.value }
func (e *policyError) Max() int      { return e.maxv }
func (e *policyError) Entry() string { return e.entry }
func (e *policyError) Cause() error  { return e.cause }

// Allows reports whether `client` is eligible for ECS forwarding
// under this policy. A nil or disabled policy never allows; otherwise
// an empty ClientNetworks means everyone, and a populated list means
// the client's address must fall inside one of the configured
// prefixes.
func (p *Policy) Allows(client netip.Addr) bool {
	if p == nil || !p.Enabled {
		return false
	}
	if !client.IsValid() {
		return false
	}
	if len(p.ClientNetworks) == 0 {
		return true
	}
	for _, n := range p.ClientNetworks {
		if n.Contains(client) {
			return true
		}
	}
	return false
}

// Clamp returns a normalised EDNS0_SUBNET safe to forward upstream
// under this policy, or nil when the input is unusable (no address,
// unsupported family). The returned option is always a fresh value
// — the caller can attach it to an outgoing OPT without aliasing
// the inbound request's storage.
//
// Source-prefix is capped to ForwardV4Max / ForwardV6Max, then the
// address is truncated to that many bits so we don't accidentally
// leak the host portion if a client sent a /32 address with a /16
// netmask (some implementations do that).
func (p *Policy) Clamp(in *dns.EDNS0_SUBNET) *dns.EDNS0_SUBNET {
	if p == nil || in == nil || in.Address == nil {
		return nil
	}

	addr, ok := ipToAddr(in.Address)
	if !ok {
		return nil
	}

	var (
		family uint16
		maxBit uint8
	)
	switch in.Family {
	case 1: // IPv4
		if !addr.Is4() {
			return nil
		}
		family, maxBit = 1, p.ForwardV4Max
	case 2: // IPv6
		if !addr.Is6() {
			return nil
		}
		family, maxBit = 2, p.ForwardV6Max
	default:
		return nil
	}

	source := min(in.SourceNetmask, maxBit)

	// Truncate the address itself to `source` bits so the wire form
	// matches what we're claiming the scope is. Without this, an
	// upstream that hashes (Address, SourceNetmask) sees inconsistent
	// state on every clamped request.
	prefix, err := addr.Prefix(int(source))
	if err != nil {
		return nil
	}

	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: source,
		SourceScope:   0, // queries always send SCOPE = 0
		Address:       prefix.Addr().AsSlice(),
	}
}

// ClampScope normalises an authoritative server's response SCOPE for
// cache-key purposes. Two RFC 7871 rules apply:
//
//   - §7.1.2: a server MUST NOT return SCOPE > SOURCE. If it does
//     (privacy violation), clamp down to SOURCE so the misbehaving
//     authority can't widen our cache key past what we forwarded.
//
//   - Stage-2 cardinality cap: scopes narrower than MinScopeV4 /
//     MinScopeV6 are widened to the minimum, capping the worst-case
//     entry count per name.
//
// Used by middleware/cache when storing a scoped answer in Stage 2.
// A nil *Policy returns the input unchanged.
func (p *Policy) ClampScope(scope, source netip.Prefix) netip.Prefix {
	if p == nil || !scope.IsValid() {
		return scope
	}

	bits := scope.Bits()
	if source.IsValid() && bits > source.Bits() {
		bits = source.Bits()
	}

	// bits is always in [0, 128] here — netip.Prefix.Bits() never
	// returns negative — so the int→uint8 conversion below is safe.
	switch {
	case scope.Addr().Is4():
		if uint8(bits) > p.MinScopeV4 { //nolint:gosec // bits ≤ 32 for v4
			bits = int(p.MinScopeV4)
		}
	case scope.Addr().Is6():
		if uint8(bits) > p.MinScopeV6 { //nolint:gosec // bits ≤ 128, fits uint8
			bits = int(p.MinScopeV6)
		}
	}

	clamped, err := scope.Addr().Prefix(bits)
	if err != nil {
		return scope
	}
	return clamped
}

// ipToAddr converts a miekg net.IP into a netip.Addr, normalising
// the 4-in-16 (::ffff:a.b.c.d) form to a 4-byte IPv4 address so the
// rest of the package can rely on Is4() / Is6() returning what the
// caller expects.
func ipToAddr(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		a, ok := netip.AddrFromSlice(v4)
		return a, ok
	}
	return netip.AddrFromSlice(ip)
}
