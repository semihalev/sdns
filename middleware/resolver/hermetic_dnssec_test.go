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
