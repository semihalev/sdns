package ecs

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestPolicy_Allows_NilOrDisabled(t *testing.T) {
	client := mustAddr(t, "203.0.113.5")

	if (*Policy)(nil).Allows(client) {
		t.Errorf("nil policy should never allow")
	}
	if (&Policy{Enabled: false}).Allows(client) {
		t.Errorf("disabled policy should never allow")
	}
}

func TestPolicy_Allows_EnabledNoNetworks(t *testing.T) {
	p := &Policy{Enabled: true}
	for _, addr := range []string{"203.0.113.5", "2001:db8::1"} {
		if !p.Allows(mustAddr(t, addr)) {
			t.Errorf("enabled+empty ClientNetworks should allow %s", addr)
		}
	}
}

func TestPolicy_Allows_ClientNetworksGate(t *testing.T) {
	p := &Policy{
		Enabled: true,
		ClientNetworks: []netip.Prefix{
			mustPrefix(t, "10.0.0.0/8"),
			mustPrefix(t, "2001:db8::/32"),
		},
	}
	allowed := []string{"10.1.2.3", "2001:db8:0:1::5"}
	denied := []string{"203.0.113.5", "192.168.1.1", "2001:db9::1"}
	for _, addr := range allowed {
		if !p.Allows(mustAddr(t, addr)) {
			t.Errorf("expected allow for %s", addr)
		}
	}
	for _, addr := range denied {
		if p.Allows(mustAddr(t, addr)) {
			t.Errorf("expected deny for %s", addr)
		}
	}
}

func TestPolicy_Clamp_NilPolicyOrInput(t *testing.T) {
	in := &dns.EDNS0_SUBNET{
		Family: 1, SourceNetmask: 24, Address: net.ParseIP("203.0.113.0").To4(),
	}
	if got := (*Policy)(nil).Clamp(in); got != nil {
		t.Errorf("nil policy should return nil, got %+v", got)
	}
	p := &Policy{Enabled: true, ForwardV4Max: 24}
	if got := p.Clamp(nil); got != nil {
		t.Errorf("nil input should return nil, got %+v", got)
	}
	if got := p.Clamp(&dns.EDNS0_SUBNET{Family: 1, SourceNetmask: 24}); got != nil {
		t.Errorf("input with no address should return nil, got %+v", got)
	}
}

func TestPolicy_Clamp_ClampsV4PrefixAndAddress(t *testing.T) {
	p := &Policy{Enabled: true, ForwardV4Max: 24}
	in := &dns.EDNS0_SUBNET{
		Family:        1,
		SourceNetmask: 32, // narrower than ceiling
		Address:       net.ParseIP("203.0.113.42").To4(),
	}
	out := p.Clamp(in)
	if out == nil {
		t.Fatal("expected clamped output, got nil")
	}
	if out.SourceNetmask != 24 {
		t.Errorf("source netmask = %d, want 24", out.SourceNetmask)
	}
	// Address must be truncated to /24 so the wire form matches what
	// we're claiming the source is — without truncation, an upstream
	// that hashes (Address, SourceNetmask) sees inconsistent state.
	if got := out.Address.String(); got != "203.0.113.0" {
		t.Errorf("address = %s, want 203.0.113.0 (host bits zeroed)", got)
	}
	if out.SourceScope != 0 {
		t.Errorf("source scope on outgoing query must be 0, got %d", out.SourceScope)
	}
	if out.Family != 1 {
		t.Errorf("family = %d, want 1", out.Family)
	}
}

func TestPolicy_Clamp_PassesNarrowerThanCeiling(t *testing.T) {
	// Client already sent /20 — the ceiling (/24) shouldn't widen.
	p := &Policy{Enabled: true, ForwardV4Max: 24}
	in := &dns.EDNS0_SUBNET{
		Family:        1,
		SourceNetmask: 20,
		Address:       net.ParseIP("203.0.96.0").To4(),
	}
	out := p.Clamp(in)
	if out == nil {
		t.Fatal("expected clamped output")
	}
	if out.SourceNetmask != 20 {
		t.Errorf("source netmask = %d, want 20 (untouched, narrower than ceiling)", out.SourceNetmask)
	}
}

func TestPolicy_Clamp_V6Family(t *testing.T) {
	p := &Policy{Enabled: true, ForwardV6Max: 56}
	in := &dns.EDNS0_SUBNET{
		Family:        2,
		SourceNetmask: 64, // narrower than ceiling
		Address:       net.ParseIP("2001:db8:1:2:3:4:5:6"),
	}
	out := p.Clamp(in)
	if out == nil {
		t.Fatal("expected clamped output")
	}
	if out.SourceNetmask != 56 {
		t.Errorf("source netmask = %d, want 56", out.SourceNetmask)
	}
	if out.Family != 2 {
		t.Errorf("family = %d, want 2", out.Family)
	}
}

func TestPolicy_Clamp_FamilyMismatchRejected(t *testing.T) {
	p := &Policy{Enabled: true, ForwardV4Max: 24, ForwardV6Max: 56}
	// Family claims IPv4 but address is IPv6.
	in := &dns.EDNS0_SUBNET{
		Family: 1, SourceNetmask: 24, Address: net.ParseIP("2001:db8::1"),
	}
	if got := p.Clamp(in); got != nil {
		t.Errorf("family/address mismatch should be rejected, got %+v", got)
	}
}

func TestPolicy_ClampScope_NilOrInvalid(t *testing.T) {
	if got := (*Policy)(nil).ClampScope(mustPrefix(t, "203.0.113.0/24"), netip.Prefix{}); got.Bits() != 24 {
		t.Errorf("nil policy should pass through, got %s", got)
	}
	p := &Policy{MinScopeV4: 24, MinScopeV6: 56}
	if got := p.ClampScope(netip.Prefix{}, netip.Prefix{}); got.IsValid() {
		t.Errorf("invalid input should pass through invalid, got %s", got)
	}
}

func TestPolicy_ClampScope_RejectsScopeNarrowerThanSource(t *testing.T) {
	// RFC 7871 §7.1.2: SCOPE > SOURCE is a privacy violation; widen
	// to source so the misbehaving authority can't push the cache
	// key past what we forwarded.
	p := &Policy{MinScopeV4: 24}
	scope := mustPrefix(t, "203.0.113.42/30") // narrower than what we forwarded
	source := mustPrefix(t, "203.0.113.0/24")
	got := p.ClampScope(scope, source)
	if got.Bits() != 24 {
		t.Errorf("scope/30 with source/24 should clamp to /24, got %s", got)
	}
}

func TestPolicy_ClampScope_EnforcesMinScope(t *testing.T) {
	p := &Policy{MinScopeV4: 24}
	scope := mustPrefix(t, "203.0.113.0/28")
	source := mustPrefix(t, "203.0.113.0/24")
	got := p.ClampScope(scope, source)
	if got.Bits() != 24 {
		t.Errorf("scope/28 with min/24 should widen to /24, got %s", got)
	}
}

func TestPolicy_ClampScope_PassesAcceptableScope(t *testing.T) {
	p := &Policy{MinScopeV4: 24, MinScopeV6: 56}
	for _, in := range []string{"203.0.113.0/24", "203.0.0.0/20", "2001:db8::/48"} {
		got := p.ClampScope(mustPrefix(t, in), netip.Prefix{})
		if got.String() != in {
			t.Errorf("acceptable scope %s should pass through, got %s", in, got)
		}
	}
}

func TestIpToAddr_V4Mapped(t *testing.T) {
	// ::ffff:203.0.113.5 is the IPv4-mapped IPv6 form of the same v4
	// address. Without normalisation the netip.Addr would report
	// Is4() == false and downstream family checks would misbehave.
	a, ok := ipToAddr(net.ParseIP("203.0.113.5"))
	if !ok || !a.Is4() {
		t.Fatalf("expected Is4() for v4 input, got ok=%v Is4=%v", ok, a.Is4())
	}
}
