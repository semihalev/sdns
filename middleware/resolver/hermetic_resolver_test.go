package resolver

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// hermeticResolve runs one query through a resolver wired to net, starting
// at its root exactly as the handler does.
func hermeticResolve(
	t *testing.T,
	r *Resolver,
	qname string,
	qtype uint16,
	configure ...func(*dns.Msg),
) (*dns.Msg, error) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	for _, apply := range configure {
		apply(req)
	}
	return r.Resolve(context.Background(), req, r.rootServers, true, 30, 0, false, nil)
}

// TestHermeticResolve is the ordinary path: a name resolves, and the
// delegation it was reached through is left in the cache, named for the
// zone it was learned for.
//
// What happens when that cached delegation stops working is a different
// story, and TestHermeticResolveRefreshesStaleAuthority tells it.
func TestHermeticResolve(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("shop.test.")
	zone.Serve(mustRR(t, "www.shop.test. 300 IN A 192.0.2.10"))

	r := net.Resolver()
	resp, err := hermeticResolve(t, r, "www.shop.test.", dns.TypeA)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatalf("resp is nil")
	} else if len(resp.Answer) == 0 {
		t.Errorf("len(resp.Answer) > 0 is false")
	}

	question := dns.Question{
		Name: "www.shop.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
	}
	match := r.searchCache(question, false, "www.shop.test.")
	if match.servers == nil || len(match.servers.List) == 0 {
		t.Fatal("the delegation used to answer was not cached")
	}

	if !reflect.DeepEqual("shop.test.", match.servers.Zone) {
		t.Errorf("match.servers.Zone = %v, want %v", match.servers.Zone, "shop.test.")
	}
	if !reflect.DeepEqual(uint32(0), atomic.LoadUint32(&match.servers.ErrorCount)) {
		t.Errorf("%s: atomic.LoadUint32(&match.servers.ErrorCount) = %v, want %v", "a delegation that answered should not be carrying failures", atomic.LoadUint32(&match.servers.ErrorCount), uint32(0))
	}
}

// TestHermeticResolveMinimize walks a deep name with QNAME minimisation on,
// so the resolver asks each cut for as little as it can and still arrives.
func TestHermeticResolveMinimize(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("deep.test.")
	zone.Serve(mustRR(t, "a.b.c.deep.test. 300 IN A 192.0.2.11"))

	cfg := net.Config()
	cfg.QnameMinLevel = 5
	handler := net.handlerWithConfig(cfg)

	resp, err := hermeticResolve(t, handler.resolver, "a.b.c.deep.test.", dns.TypeA,
		func(m *dns.Msg) { m.CheckingDisabled = true })

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatalf("resp is nil")
	} else if len(resp.Answer) == 0 {
		t.Errorf("len(resp.Answer) > 0 is false")
	}
}

// TestHermeticResolveNXDOMAIN asks for a name the root does not delegate.
// A denial is an answer, not a failure.
func TestHermeticResolveNXDOMAIN(t *testing.T) {
	net := newHermeticNet(t)

	resp, err := hermeticResolve(t, net.Resolver(), "nothing-here.", dns.TypeNS)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatalf("resp is nil")
	} else if !reflect.DeepEqual(dns.RcodeNameError, resp.Rcode) {
		t.Errorf("resp.Rcode = %v, want %v", resp.Rcode, dns.RcodeNameError)
	}
}

// TestHermeticResolveEmptyNonTerminal asks for a label that only exists
// because something is delegated beneath it. Such a name holds no records
// but is not absent, so the answer is NODATA — denying it would deny the
// whole subtree, and a resolver walking down to that subtree would then be
// relying on its broken-parent fallback to get anywhere.
func TestHermeticResolveEmptyNonTerminal(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("ent.test.")
	zone.Serve(mustRR(t, "www.ent.test. 300 IN A 192.0.2.14"))

	resp, err := hermeticResolve(t, net.Resolver(), "test.", dns.TypeA)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("resp is nil")
	} else {
		if !reflect.DeepEqual(dns.RcodeSuccess, resp.Rcode) {
			t.Errorf("%s: resp.Rcode = %v, want %v", "a label above a delegation exists; denying it denies the subtree", resp.Rcode, dns.RcodeSuccess)
		}
		if !reflect.DeepEqual(0, len(resp.Answer)) {
			t.Errorf("len(resp.Answer) = %v, want %v", len(resp.Answer), 0)
		}
	}
}

// TestHermeticResolveNODATA asks an existing name for a type it does not
// have. That too is an answer, and it must not be reported as an error.
func TestHermeticResolveNODATA(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("nodata2.test.")
	zone.Serve(mustRR(t, "host.nodata2.test. 300 IN A 192.0.2.12"))

	resp, err := hermeticResolve(t, net.Resolver(), "host.nodata2.test.", dns.TypeAAAA)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatalf("resp is nil")
	} else {
		if !reflect.DeepEqual(dns.RcodeSuccess, resp.Rcode) {
			t.Errorf("resp.Rcode = %v, want %v", resp.Rcode, dns.RcodeSuccess)
		}
		if !reflect.DeepEqual(0, len(resp.Answer)) {
			t.Errorf("len(resp.Answer) = %v, want %v", len(resp.Answer), 0)
		}
	}
}

// TestHermeticResolveUnreachableAuthority pins that a zone whose authority
// never answers fails rather than hanging or inventing a reply.
func TestHermeticResolveUnreachableAuthority(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("dead.test.")
	zone.Serve(mustRR(t, "www.dead.test. 300 IN A 192.0.2.13"))
	zone.Silence()

	// The default two-second budget is spent waiting for a reply that will
	// never come; nothing here needs that long to establish silence.
	cfg := net.Config()
	cfg.Timeout.Duration = 200 * time.Millisecond
	r := net.handlerWithConfig(cfg).resolver

	_, err := hermeticResolve(t, r, "www.dead.test.", dns.TypeA)

	if err == nil {
		t.Errorf("expected an error, got nil")
	}
}

// TestHermeticResolveRootKeys pins that the root's own DNSKEY resolves,
// which is the query the chain of trust starts from.
func TestHermeticResolveRootKeys(t *testing.T) {
	net := newHermeticNet(t)

	resp, err := hermeticResolve(t, net.Resolver(), ".", dns.TypeDNSKEY)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatalf("resp is nil")
	} else if len(resp.Answer) == 0 {
		t.Errorf("len(resp.Answer) > 0 is false")
	}
}
