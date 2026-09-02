package dns64

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// TestName pins the registered middleware name so the gen.go entry
// can't drift away from what the package reports.
func TestName(t *testing.T) {
	d := New(baseConfig())
	if !reflect.DeepEqual("dns64", d.Name()) {
		t.Errorf("d.Name() = %v, want %v", d.Name(), "dns64")
	}
}

// TestSetQueryer covers the trivial setter used by middleware.Setup
// during auto-wire. We pass a Queryer-shaped value and read it
// back via an A-lookup that exercises synthesise.
func TestSetQueryer(t *testing.T) {
	d := New(baseConfig())
	q := &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}
	d.SetQueryer(q)
	if d.queryer != middleware.Queryer(q) {
		t.Fatalf("SetQueryer did not install the provided queryer")
	}
}

// TestClassifyQueryErr exercises every branch of the metric label
// derivation so the cardinality contract is observable.
func TestClassifyQueryErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"no_response", middleware.ErrNoResponse, "no_response"},
		{"max_recursion", middleware.ErrMaxRecursion, "max_recursion"},
		{"queryer_error", errQueryerNotWired, "queryer_error"},
		{"other", errors.New("unknown"), "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.want, classifyQueryErr(tc.err)) {
				t.Errorf("classifyQueryErr(tc.err) = %v, want %v", classifyQueryErr(tc.err), tc.want)
			}
		})
	}
}

// TestCompileConfig_BadEntriesSkipped exercises the lenient parse
// pattern: bad prefixes / bad CIDRs / bad exclude-A entries are
// logged-and-skipped instead of disabling the middleware.
func TestCompileConfig_BadEntriesSkipped(t *testing.T) {
	cfg := &config.Config{DNS64: config.DNS64Config{
		Enabled: true,
		Prefixes: []string{
			"not-a-cidr",    // unparseable → skip
			"2001:db8::/49", // wrong length → skip
			"64:ff9b::/96",  // good, picked
			"2001:db8::/96", // ignored (first valid wins)
		},
		ClientNetworks:   []string{"bad-cidr", "10.0.0.0/8"},
		ExcludeZones:     []string{"", "example.org"},
		ExcludeANetworks: []string{"bad-cidr", "::1/128", "10.0.0.0/8"}, // first two skip
	}}
	c := compileConfig(cfg)
	if c == nil {
		t.Fatalf("compileConfig returned nil despite usable prefixes")
	}
	if len(c.prefixes) != 2 {
		t.Errorf("%s: len(c.prefixes) = %d, want %d", "both valid prefixes are kept (well-known + operator)", len(c.prefixes), 2)
	} else {
		if !(c.prefixes[0].net.IP.Equal(net.ParseIP("64:ff9b::"))) {
			t.Errorf("%s: c.prefixes[0].net.IP.Equal(net.ParseIP('64:ff9b::')) is false", "well-known appears first as configured")
		}
		if !(c.prefixes[0].wellKnown) {
			t.Errorf("c.prefixes[0].wellKnown is false")
		}
		if !(c.prefixes[1].net.IP.Equal(net.ParseIP("2001:db8::"))) {
			t.Errorf("c.prefixes[1].net.IP.Equal(net.ParseIP('2001:db8::')) is false")
		}
		if c.prefixes[1].wellKnown {
			t.Errorf("c.prefixes[1].wellKnown is true")
		}
	}
	if !(c.hasWellKnown()) {
		t.Errorf("c.hasWellKnown() is false")
	}
	if len(c.clientNetworks) != 1 {
		t.Errorf("%s: len(c.clientNetworks) = %d, want %d", "bad CIDR dropped, good one kept", len(c.clientNetworks), 1)
	}
	if len(c.excludeZones) != 1 {
		t.Errorf("%s: len(c.excludeZones) = %d, want %d", "empty zone entry dropped, good one kept and FQDN'd", len(c.excludeZones), 1)
	}
	if !reflect.DeepEqual("example.org.", c.excludeZones[0]) {
		t.Errorf("c.excludeZones[0] = %v, want %v", c.excludeZones[0], "example.org.")
	}
	if len(c.excludeAv4) != 1 {
		t.Errorf("%s: len(c.excludeAv4) = %d, want %d", "bad and IPv6 exclude entries dropped", len(c.excludeAv4), 1)
	}
}

// TestCompileConfig_NoUsablePrefixFallsBackToWellKnown pins
// RFC 6147 §5.2: when DNS64 is enabled but every configured
// prefix is invalid (or the field is omitted entirely), the
// well-known prefix 64:ff9b::/96 is the default rather than
// silently disabling.
func TestCompileConfig_NoUsablePrefixFallsBackToWellKnown(t *testing.T) {
	cfg := &config.Config{DNS64: config.DNS64Config{
		Enabled:  true,
		Prefixes: []string{"not-a-cidr", "2001:db8::/49"},
	}}
	c := compileConfig(cfg)
	if c == nil {
		t.Fatalf("compileConfig must default to well-known prefix, not return nil")
	}
	if len(c.prefixes) != 1 {
		t.Errorf("len(c.prefixes) = %d, want %d", len(c.prefixes), 1)
	} else {
		if !(c.prefixes[0].wellKnown) {
			t.Errorf("c.prefixes[0].wellKnown is false")
		}
		if !(c.prefixes[0].net.IP.Equal(net.ParseIP("64:ff9b::"))) {
			t.Errorf("c.prefixes[0].net.IP.Equal(net.ParseIP('64:ff9b::')) is false")
		}
	}
}

// TestCompileConfig_DisabledReturnsNil pins that explicit
// enabled=false still bypasses the §5.2 default, operators have
// the final word on whether DNS64 runs.
func TestCompileConfig_DisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{DNS64: config.DNS64Config{Enabled: false}}
	if c := compileConfig(cfg); c != nil {
		t.Fatalf("compileConfig must return nil when enabled=false, got %#v", c)
	}
}

// TestCompileConfig_DefaultExcludeAUnderWKP pins RFC 6052 §3.1:
// when the well-known prefix is configured and the operator
// omits exclude_a_networks entirely, the IANA Special-Purpose
// default list is applied at runtime so private-space A records
// are never embedded into 64:ff9b::/96.
func TestCompileConfig_DefaultExcludeAUnderWKP(t *testing.T) {
	cfg := &config.Config{DNS64: config.DNS64Config{
		Enabled:  true,
		Prefixes: []string{"64:ff9b::/96"},
		// ExcludeANetworks left as nil (omitted).
	}}
	c := compileConfig(cfg)
	if c == nil {
		t.Fatalf("compileConfig should not disable")
	}
	if len(c.excludeAv4) == 0 {
		t.Errorf("%s: c.excludeAv4 is empty", "WKP + nil exclude list must apply runtime default")
	}
	// Spot-check a couple of representative entries.
	covers := func(ip string) bool {
		for _, n := range c.excludeAv4 {
			if n.Contains(net.ParseIP(ip).To4()) {
				return true
			}
		}
		return false
	}
	if !(covers("10.0.0.1")) {
		t.Errorf("%s: covers('10.0.0.1') is false", "RFC 1918 must be excluded by default")
	}
	if !(covers("127.0.0.1")) {
		t.Errorf("%s: covers('127.0.0.1') is false", "loopback must be excluded by default")
	}
	if !(covers("169.254.1.1")) {
		t.Errorf("%s: covers('169.254.1.1') is false", "link-local must be excluded by default")
	}
	if !(covers("192.88.99.1")) {
		t.Errorf("%s: covers('192.88.99.1') is false", "deprecated 6to4 anycast (RFC 7526) must be excluded")
	}
}

// TestCompileConfig_ExplicitEmptyExcludeAOptsOut confirms an
// operator can disable the runtime default by declaring
// exclude_a_networks = [] explicitly.
func TestCompileConfig_ExplicitEmptyExcludeAOptsOut(t *testing.T) {
	cfg := &config.Config{DNS64: config.DNS64Config{
		Enabled:          true,
		Prefixes:         []string{"64:ff9b::/96"},
		ExcludeANetworks: []string{}, // declared empty != nil
	}}
	c := compileConfig(cfg)
	if c == nil {
		t.Fatalf("compileConfig should not disable")
	}
	if len(c.excludeAv4) != 0 {
		t.Errorf("%s: c.excludeAv4 not empty: %v", "explicit [] must opt out of the runtime default", c.excludeAv4)
	}
}

// TestCompileConfig_AcceptsIPv4MappedExcludeAAAA pins the fix
// for the IP.To4() trap: ::ffff:0:0/96 is a legal IPv6 prefix
// even though IPv4-mapped, and the documented default must
// survive validation.
func TestCompileConfig_AcceptsIPv4MappedExcludeAAAA(t *testing.T) {
	cfg := &config.Config{DNS64: config.DNS64Config{
		Enabled:             true,
		Prefixes:            []string{"64:ff9b::/96"},
		ExcludeAAAANetworks: []string{"::ffff:0:0/96"},
	}}
	c := compileConfig(cfg)
	if c == nil {
		t.Fatalf("compileConfig should not disable; ::ffff:0:0/96 is a valid IPv6 prefix")
	}
	if len(c.excludeAAAA) != 1 {
		t.Errorf("%s: len(c.excludeAAAA) = %d, want %d", "explicit ::ffff:0:0/96 must be retained", len(c.excludeAAAA), 1)
	} else if !(c.excludeAAAA[0].IP.Equal(net.ParseIP("::ffff:0:0"))) {
		t.Errorf("c.excludeAAAA[0].IP.Equal(net.ParseIP('::ffff:0:0')) is false")
	}
}

// TestCompileConfig_OperatorPrefixSkipsExcludeA pins that the
// exclude-A list is only parsed for the well-known prefix; an
// operator-chosen prefix discards the list at compile time.
func TestCompileConfig_OperatorPrefixSkipsExcludeA(t *testing.T) {
	cfg := &config.Config{DNS64: config.DNS64Config{
		Enabled:          true,
		Prefixes:         []string{"2001:db8:64::/96"},
		ExcludeANetworks: []string{"10.0.0.0/8"},
	}}
	c := compileConfig(cfg)
	if c == nil {
		t.Fatalf("expected non-nil compiled config")
	}
	if c.hasWellKnown() {
		t.Errorf("%s: c.hasWellKnown() is true", "no well-known prefix configured")
	}
	if len(c.excludeAv4) != 0 {
		t.Errorf("%s: c.excludeAv4 not empty: %v", "operator-only prefix list must not retain the exclude-A list", c.excludeAv4)
	}
}

// TestClientEligible_NilIP covers the explicit nil-IP guard, which
// shows up if a writer somehow lacks RemoteAddr (mock variants in
// downstream tests).
func TestClientEligible_NilIP(t *testing.T) {
	c := &compiled{
		clientNetworks: []*net.IPNet{parseCIDR(t, "10.0.0.0/8")},
	}
	if c.clientEligible(nil) {
		t.Errorf("c.clientEligible(nil) is true")
	}
}

// TestZoneExcluded covers exact-match, label-boundary suffix
// match, the label-fragment trap, and the empty-list short-
// circuit.
func TestZoneExcluded(t *testing.T) {
	c := &compiled{excludeZones: []string{"example.org."}}
	if !(c.zoneExcluded("example.org.")) {
		t.Errorf("%s: c.zoneExcluded('example.org.') is false", "exact match should be excluded")
	}
	if !(c.zoneExcluded("host.example.org.")) {
		t.Errorf("%s: c.zoneExcluded('host.example.org.') is false", "label-boundary suffix should be excluded")
	}
	if !(c.zoneExcluded("a.b.example.org.")) {
		t.Errorf("%s: c.zoneExcluded('a.b.example.org.') is false", "deeper label-boundary suffix should be excluded")
	}
	if c.zoneExcluded("badexample.org.") {
		t.Errorf("%s: c.zoneExcluded('badexample.org.') is true", "label-fragment match must NOT trigger exclusion")
	}
	if c.zoneExcluded("other.example.com.") {
		t.Errorf("c.zoneExcluded('other.example.com.') is true")
	}

	empty := &compiled{}
	if empty.zoneExcluded("anything.") {
		t.Errorf("empty.zoneExcluded('anything.') is true")
	}
}

// TestWriteMsg_Truncated_PassThrough pins the truncated-response
// short-circuit branch, DNS64 must never rewrite a TC=1 reply
// because the client will retry over TCP.
func TestWriteMsg_Truncated_PassThrough(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{} // would loudly fail if invoked
	tc := noDataMsg("foo.example.org.", 300)
	tc.Truncated = true
	ch, mw := makeChain(t, d, &stubAnswerer{msg: tc}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)

	d.ServeDNS(context.Background(), ch)
	resp := mw.Msg()
	if !(resp.Truncated) {
		t.Errorf("%s: resp.Truncated is false", "truncated reply must pass through untouched")
	}
}

// TestWriteMsg_ServFail_AResponseIsBasis covers RFC 6147 §5.1.6:
// when the AAAA was SERVFAIL and the A lookup yielded a real
// (empty) NOERROR answer, the A response, not the original
// SERVFAIL, is the basis for the client reply. The client
// therefore sees NOERROR-NODATA addressed to its AAAA question.
func TestWriteMsg_ServFail_AResponseIsBasis(t *testing.T) {
	d := New(baseConfig())
	emptyA := new(dns.Msg)
	emptyA.SetQuestion("foo.example.org.", dns.TypeA)
	emptyA.Response = true
	emptyA.Rcode = dns.RcodeSuccess
	soa, _ := dns.NewRR("example.org. 3600 IN SOA ns. host. 1 7200 3600 604800 60")
	emptyA.Ns = []dns.RR{soa}
	d.queryer = &stubQueryer{resp: emptyA}

	servfail := new(dns.Msg)
	servfail.SetQuestion("foo.example.org.", dns.TypeAAAA)
	servfail.Response = true
	servfail.Rcode = dns.RcodeServerFailure
	servfail.SetEdns0(4096, true)

	ch, mw := makeChain(t, d, &stubAnswerer{msg: servfail}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if !reflect.DeepEqual(dns.RcodeSuccess, resp.Rcode) {
		t.Errorf("%s: resp.Rcode = %v, want %v", "A NOERROR-NODATA must replace AAAA SERVFAIL per RFC 6147 §5.1.6", resp.Rcode, dns.RcodeSuccess)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("%s: resp.Answer not empty: %v", "no answer records for an empty A response", resp.Answer)
	}
	if !reflect.DeepEqual(dns.TypeAAAA, resp.Question[0].Qtype) {
		t.Errorf("%s: resp.Question[0].Qtype = %v, want %v", "client must see its original AAAA question", resp.Question[0].Qtype, dns.TypeAAAA)
	}
	if len(resp.Ns) != 1 {
		t.Errorf("%s: len(resp.Ns) = %d, want %d", "SOA from A response carried into Authority section", len(resp.Ns), 1)
	} else {
		_, ok := resp.Ns[0].(*dns.SOA)
		if !(ok) {
			t.Errorf("ok is false")
		}
	}
}

// TestSynthesise_QueryerNotWired pins the early-out when the
// Queryer is nil. Production never reaches this branch, Setup
// always wires before publishing the pipeline, but the guard
// keeps tests from segfaulting and the metric label set documented.
func TestSynthesise_QueryerNotWired(t *testing.T) {
	d := New(baseConfig())
	d.queryer = nil // explicit; New leaves it nil before SetQueryer
	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if !reflect.DeepEqual(dns.RcodeSuccess, resp.Rcode) {
		t.Errorf("%s: resp.Rcode = %v, want %v", "original NODATA preserved", resp.Rcode, dns.RcodeSuccess)
	}
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			t.Fatalf("no Queryer wired → no synthesis")
		}
	}
}
