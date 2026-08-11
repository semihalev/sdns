package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

func hermeticAsk(t *testing.T, handler *DNSHandler, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	return handler.handle(context.Background(), req)
}

// TestHermeticDNSSECSecure pins that the fixture reaches a validated answer:
// the chain runs from the configured trust anchor through the root's DS to
// the child's key, and the resolver says so with AD.
func TestHermeticDNSSECSecure(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("secure.test.")
	zone.Serve(mustRR(t, "www.secure.test. 300 IN A 192.0.2.10"))

	resp := hermeticAsk(t, net.Handler(), "www.secure.test.", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if !resp.AuthenticatedData {
		t.Fatal("a fully signed chain must come back authenticated; " +
			"AD=0 means validation never ran rather than that it failed")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("no answer returned")
	}
	if zone.asked("secure.test.", dns.TypeDNSKEY) == 0 {
		t.Fatal("the child's key was never fetched, so nothing was validated")
	}
}

// TestHermeticDNSSECZoneApex asks the child's own apex. The name sits on
// the cut, so the parent must refer it rather than answer for it — the DS
// is the only record there the parent legitimately holds.
func TestHermeticDNSSECZoneApex(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("apex.test.")
	zone.Serve(mustRR(t, "apex.test. 300 IN A 192.0.2.90"))

	resp := hermeticAsk(t, net.Handler(), "apex.test.", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if !resp.AuthenticatedData {
		t.Fatal("the apex answer came back unauthenticated")
	}
	if zone.asked("apex.test.", dns.TypeA) == 0 {
		t.Fatal("the apex query never reached the zone that owns it")
	}
}

// TestHermeticDNSSECBogusFailsClosed restores at the handler level what a
// live "signed zone, missing signatures" probe used to cover: the answer is
// refused, nothing is served, and the response carries an EDE saying why.
func TestHermeticDNSSECBogusFailsClosed(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("bogus.test.")
	// A signed zone that answers without a signature.
	zone.ServeUnsigned(mustRR(t, "www.bogus.test. 300 IN A 192.0.2.20"))

	resp := hermeticAsk(t, net.Handler(), "www.bogus.test.", dns.TypeA)

	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL: an unsigned answer from a signed "+
			"zone must fail closed", dns.RcodeToString[resp.Rcode])
	}
	if resp.AuthenticatedData {
		t.Fatal("a refused answer must not be marked authenticated")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("SERVFAIL carries %d answers", len(resp.Answer))
	}

	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT record, so no extended error reached the client")
	}
	var ede *dns.EDNS0_EDE
	for _, option := range opt.Option {
		if found, ok := option.(*dns.EDNS0_EDE); ok {
			ede = found
			break
		}
	}
	if ede == nil {
		t.Fatal("no EDE option: the client is told the query failed but not why")
	}
	if ede.InfoCode != dns.ExtendedErrorCodeRRSIGsMissing {
		t.Fatalf("EDE code = %d (%s), want RRSIGsMissing",
			ede.InfoCode, dns.ExtendedErrorCodeToString[ede.InfoCode])
	}
}

// TestHermeticDNSSECBogusResolveError pins the failure by identity, one
// layer below the response: callers switch on this error, and only the
// resolver's return value carries it.
func TestHermeticDNSSECBogusResolveError(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("nosig.test.")
	zone.ServeUnsigned(mustRR(t, "www.nosig.test. 300 IN A 192.0.2.50"))

	r := net.Resolver()
	req := new(dns.Msg)
	req.SetQuestion("www.nosig.test.", dns.TypeA)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	resp, err := r.Resolve(context.Background(), req, r.rootServers, true, 30, 0, false, nil)
	if err == nil {
		t.Fatal("an unsigned answer from a signed zone must not resolve")
	}
	if !errors.Is(err, dnssec.ErrNoSignatures) {
		t.Fatalf("error is %v, want dnssec.ErrNoSignatures", err)
	}
	if resp != nil {
		t.Fatalf("a refused resolution returned a response with %d answers",
			len(resp.Answer))
	}
}

// TestHermeticDNSSECWrongDSFailsClosed breaks the chain at the cut rather
// than at the answer: the parent's DS describes a key the child does not
// hold, so every signature the child offers is unverifiable.
func TestHermeticDNSSECWrongDSFailsClosed(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.DelegateWrongDS("wrongds.test.")
	zone.Serve(mustRR(t, "www.wrongds.test. 300 IN A 192.0.2.60"))

	resp := hermeticAsk(t, net.Handler(), "www.wrongds.test.", dns.TypeA)

	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL: a DS that matches no key in the "+
			"child breaks the chain", dns.RcodeToString[resp.Rcode])
	}
	if resp.AuthenticatedData {
		t.Fatal("a broken chain must not be reported as authenticated")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("SERVFAIL carries %d answers", len(resp.Answer))
	}
}

// TestHermeticDNSSECNSEC3NODATA covers the hashed-denial path. NSEC and
// NSEC3 are verified by different code in the resolver, so a fixture that
// only ever produces NSEC leaves the other branch untouched — which is what
// the removed Test_resolverNSEC3nodata used a third-party zone for.
func TestHermeticDNSSECNSEC3NODATA(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.DelegateNSEC3("hashed.test.")
	zone.Serve(mustRR(t, "host.hashed.test. 300 IN A 192.0.2.95"))

	resp := hermeticAsk(t, net.Handler(), "host.hashed.test.", dns.TypeAAAA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR: a name without the queried type "+
			"is NODATA", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("NODATA carries %d answers", len(resp.Answer))
	}
	if !resp.AuthenticatedData {
		t.Fatal("a signed NSEC3 denial must come back authenticated; AD=0 " +
			"means the proof was not verified")
	}
}

// TestHermeticDNSSECNSEC3NameError covers the hashed proof that a name does
// not exist. RFC 5155 §8.4 wants three things together — a record matching
// the closest encloser, one covering the next closer, and one covering the
// wildcard beneath the closest encloser — and they are what the zone's
// NSEC3 chain supplies.
func TestHermeticDNSSECNSEC3NameError(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.DelegateNSEC3("nx3.test.")
	zone.Serve(mustRR(t, "host.nx3.test. 300 IN A 192.0.2.96"))

	for _, qname := range []string{
		// Directly beneath the apex: the next closer is the name itself.
		"absent.nx3.test.",
		// Deeper, so the closest encloser is still the apex but the next
		// closer is an intermediate name that does not exist either.
		"a.b.absent.nx3.test.",
	} {
		t.Run(qname, func(t *testing.T) {
			resp := hermeticAsk(t, net.Handler(), qname, dns.TypeA)

			if resp.Rcode != dns.RcodeNameError {
				t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
			}
			if !resp.AuthenticatedData {
				t.Fatal("a signed NSEC3 denial must come back authenticated; " +
					"AD=0 means the proof was not verified")
			}
			if len(resp.Answer) != 0 {
				t.Fatalf("NXDOMAIN carries %d answers", len(resp.Answer))
			}
		})
	}
}

// TestHermeticDNSSECInsecureDelegation pins the other half of fail-closed:
// a zone with no DS at the cut is unsigned, not broken, so its answers are
// served — just not authenticated.
func TestHermeticDNSSECInsecureDelegation(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.DelegateInsecure("plain.test.")
	zone.Serve(mustRR(t, "www.plain.test. 300 IN A 192.0.2.30"))

	resp := hermeticAsk(t, net.Handler(), "www.plain.test.", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR: an insecure delegation is not a "+
			"validation failure", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("no answer returned")
	}
	if resp.AuthenticatedData {
		t.Fatal("an unsigned zone must not be reported as authenticated")
	}
}

// TestHermeticDNSSECNODATA covers a signed negative answer for a name that
// exists without the queried type — the shape Test_resolverNSEC3nodataerror
// used a third-party zone for.
func TestHermeticDNSSECNODATA(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("nodata.test.")
	zone.Serve(mustRR(t, "host.nodata.test. 300 IN A 192.0.2.40"))

	resp := hermeticAsk(t, net.Handler(), "host.nodata.test.", dns.TypeDS)

	// A DS query at a name with no delegation must not be answered from the
	// child, and must not fail closed either.
	if resp.Rcode == dns.RcodeServerFailure {
		t.Fatal("a missing DS must not surface as SERVFAIL")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("DS query returned %d answers for an undelegated name",
			len(resp.Answer))
	}
}

// TestHermeticDNSSECNSEC3OptOut pins what an Opt-Out span is worth. Such a
// span may contain unsigned delegations, so a denial resting on one does
// not establish that the name is absent — the answer may be served, but it
// must not be presented as authenticated (RFC 5155 §6, §9.2).
func TestHermeticDNSSECNSEC3OptOut(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.DelegateNSEC3OptOut("optout.test.")
	zone.Serve(mustRR(t, "host.optout.test. 300 IN A 192.0.2.97"))

	resp := hermeticAsk(t, net.Handler(), "absent.optout.test.", dns.TypeA)

	// The distinction §9.2 draws is between accepting the answer and
	// vouching for it. Refusing Opt-Out denials outright would satisfy an
	// AD check on its own, so the denial itself is pinned too.
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN: an Opt-Out span still denies the "+
			"name, it just cannot be vouched for", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("NXDOMAIN carries %d answers", len(resp.Answer))
	}
	if resp.AuthenticatedData {
		t.Fatal("a denial resting on an Opt-Out span was reported as " +
			"authenticated; the span may hide an unsigned delegation")
	}
}

// TestHermeticDNSSECDenialWithoutCoverageRefused is the negative case the
// positive ones cannot make: a zone that answers a denial with records that
// cover nothing. The proof is signed and well formed, so a validator that
// only checks signatures accepts it — and would then accept a denial for a
// name that exists. Both denial families are checked, since each is
// verified by its own code.
func TestHermeticDNSSECDenialWithoutCoverageRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		delegate func(*hermeticNet, string) *hermeticZone
	}{
		{
			name: "nsec",
			delegate: func(n *hermeticNet, zone string) *hermeticZone {
				return n.Delegate(zone)
			},
		},
		{
			name: "nsec3",
			delegate: func(n *hermeticNet, zone string) *hermeticZone {
				return n.DelegateNSEC3(zone)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := newHermeticNet(t)
			zone := tc.delegate(net, "nocover-"+tc.name+".test.")
			zone.Serve(mustRR(t, "host.nocover-"+tc.name+".test. 300 IN A 192.0.2.98"))
			zone.WithholdDenialCoverage()

			resp := hermeticAsk(t, net.Handler(),
				"absent.nocover-"+tc.name+".test.", dns.TypeA)

			// Refusing has to mean SERVFAIL. Anything else — NODATA,
			// REFUSED, an empty NOERROR — would let a resolver that quietly
			// gave up pass a test that only ruled out NXDOMAIN.
			if resp.Rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode = %s, want SERVFAIL: a denial that covers "+
					"nothing must be refused", dns.RcodeToString[resp.Rcode])
			}
			if resp.AuthenticatedData {
				t.Fatal("a denial whose records cover nothing was reported as " +
					"authenticated")
			}
			if len(resp.Answer) != 0 {
				t.Fatalf("SERVFAIL carries %d answers", len(resp.Answer))
			}

			// And the client should be told why.
			if opt := resp.IsEdns0(); opt != nil {
				for _, option := range opt.Option {
					ede, ok := option.(*dns.EDNS0_EDE)
					if !ok {
						continue
					}
					if ede.InfoCode != dns.ExtendedErrorCodeNSECMissing {
						t.Fatalf("EDE code = %d (%s), want NSECMissing",
							ede.InfoCode, dns.ExtendedErrorCodeToString[ede.InfoCode])
					}
				}
			}
		})
	}
}
