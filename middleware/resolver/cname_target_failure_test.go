package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/edns"
)

// aliasFixture is a signed alias, www.alias.test. CNAME www.target.test.,
// behind the client-facing chain the server builds: the EDNS layer, the
// cache, the resolver.
type aliasFixture struct {
	target *hermeticZone
	cache  *answercache.Cache
	client []middleware.Handler
}

func newAliasFixture(t *testing.T) *aliasFixture {
	t.Helper()
	net := newHermeticNet(t)
	target := net.Delegate("target.test.")
	// A CNAME answers every question at its owner, as a real zone serves it.
	alias := net.Delegate("alias.test.")
	cname := mustRR(t, "www.alias.test. 300 IN CNAME www.target.test.")
	alias.Serve(cname)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		alias.server.serve("www.alias.test.", qtype, cname, alias.key.sign(t, []dns.RR{cname}))
	}

	cfg := net.Config()
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	cache := answercache.New(cfg)
	cache.SetDNSSECCryptoLimiter(handler.DNSSECCryptoLimiter())
	handlers := []middleware.Handler{cache, handler}
	// The wiring middleware.Setup does in the server: the cache chases an
	// alias's target through the same pipeline.
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	cache.SetQueryer(queryer)
	return &aliasFixture{
		target: target,
		cache:  cache,
		client: append([]middleware.Handler{edns.New(cfg)}, handlers...),
	}
}

// serveTarget publishes the target's A RRset, soundly signed or with a
// signature that does not verify. Only the A RRset is ever tampered with,
// so the questions are for A; the zone's other data stays sound.
func (f *aliasFixture) serveTarget(t *testing.T, bogus bool) {
	t.Helper()
	served := mustRR(t, "www.target.test. 300 IN A 192.0.2.80")
	if bogus {
		f.target.ServeTampered([]dns.RR{served}, mustRR(t, "www.target.test. 300 IN A 198.51.100.80"))
		return
	}
	f.target.Serve(served)
}

func (f *aliasFixture) ask(t *testing.T, withEDNS bool) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion("www.alias.test.", dns.TypeA)
	if withEDNS {
		req.SetEdns0(1232, true)
	}
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain(f.client)
	ch.Reset(w, req)
	ch.Next(context.Background())
	if !w.Written() {
		t.Fatal("no reply")
	}
	return w.Msg()
}

// wantAliasFailure checks one answer to an alias whose target fails: SERVFAIL,
// nothing of the alias left, no AD, and the target's own EDE, or no OPT at
// all for a client that asked without EDNS.
func wantAliasFailure(t *testing.T, step string, resp *dns.Msg, withEDNS bool, ede uint16) {
	t.Helper()
	if resp.Rcode != dns.RcodeServerFailure || resp.AuthenticatedData || len(resp.Answer) != 0 {
		t.Fatalf("%s: %s AD=%v %v, want SERVFAIL for an alias whose target is bogus",
			step, dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
	}
	switch {
	case withEDNS && !hasEDE(resp, ede):
		t.Fatalf("%s: want the target's EDE %d, got:\n%v", step, ede, resp)
	case !withEDNS && resp.IsEdns0() != nil:
		t.Fatalf("%s: an OPT reached a client that asked without EDNS", step)
	}
}

// A CNAME whose target cannot be resolved does not leave the alias standing
// on its own: the client asked for the target's data, and an answer that
// ends at the alias with AD set tells it that data provably exists and is
// what it got. A bogus target is a validation failure of the whole answer,
// SERVFAIL, carrying the target's Extended DNS Error. The control, a sound
// target, shows the answer really comes through the alias.
func TestCNAMEToAFailingTargetIsNotAnAnswer(t *testing.T) {
	t.Run("sound target", func(t *testing.T) {
		f := newAliasFixture(t)
		f.serveTarget(t, false)
		for _, withEDNS := range []bool{true, true, false} {
			resp := f.ask(t, withEDNS)
			if resp.Rcode != dns.RcodeSuccess || !hasType(resp, dns.TypeA) ||
				(withEDNS && !resp.AuthenticatedData) {
				t.Fatalf("%s AD=%v %v, want the validated alias and target",
					dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
			}
		}
	})

	// The whole question resolves: the alias fails with the target's DNSSEC
	// Bogus, and later asks are the failure cache's (RFC 9520), which says
	// the same: the target never asked again.
	t.Run("bogus target, alias resolved", func(t *testing.T) {
		f := newAliasFixture(t)
		f.serveTarget(t, true)
		wantAliasFailure(t, "resolved", f.ask(t, true), true, dns.ExtendedErrorCodeDNSBogus)
		asked := f.target.asked("www.target.test.", dns.TypeA)
		wantAliasFailure(t, "again", f.ask(t, true), true, dns.ExtendedErrorCodeDNSBogus)
		wantAliasFailure(t, "without EDNS", f.ask(t, false), false, 0)
		if again := f.target.asked("www.target.test.", dns.TypeA); again != asked {
			t.Fatalf("the target was asked %d more times, want the failure cache's answers", again-asked)
		}
	})

	// The alias was cached while its target was sound, and the target has
	// failed since. The alias is served from the cache, which materializes it
	// without an OPT, and the chase fails: the target's EDE must still reach
	// the client, DNSSEC Bogus when the target resolves and again once its
	// failure is cached.
	t.Run("bogus target, alias served from the cache", func(t *testing.T) {
		f := newAliasFixture(t)
		f.serveTarget(t, false)
		if resp := f.ask(t, true); resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
			t.Fatalf("priming: %s AD=%v, want the validated answer", dns.RcodeToString[resp.Rcode], resp.AuthenticatedData)
		}
		f.serveTarget(t, true)
		f.cache.Purge(dns.Question{Name: "www.target.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

		wantAliasFailure(t, "first", f.ask(t, true), true, dns.ExtendedErrorCodeDNSBogus)
		asked := f.target.asked("www.target.test.", dns.TypeA)
		wantAliasFailure(t, "second", f.ask(t, true), true, dns.ExtendedErrorCodeDNSBogus)
		wantAliasFailure(t, "third", f.ask(t, true), true, dns.ExtendedErrorCodeDNSBogus)
		wantAliasFailure(t, "without EDNS", f.ask(t, false), false, 0)
		if again := f.target.asked("www.target.test.", dns.TypeA); again != asked {
			t.Fatalf("the target was asked %d more times, want the failure cache's answers", again-asked)
		}
	})
}

func hasEDE(m *dns.Msg, code uint16) bool {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == code {
				return true
			}
		}
	}
	return false
}

func hasType(m *dns.Msg, t uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}
