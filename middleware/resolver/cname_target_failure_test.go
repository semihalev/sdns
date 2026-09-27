package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
)

// A CNAME whose target cannot be resolved does not leave the alias standing
// on its own: the client asked for the target's data, and an answer that
// ends at the alias with AD set tells it that data provably exists and is
// what it got. A bogus target is a validation failure of the whole answer,
// SERVFAIL. The control, a sound target, shows the answer really comes
// through the alias.
func TestCNAMEToAFailingTargetIsNotAnAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bogus bool
	}{{"sound target", false}, {"target with a bad signature", true}} {
		t.Run(tc.name, func(t *testing.T) {
			net := newHermeticNet(t)
			target := net.Delegate("target.test.")
			served := mustRR(t, "www.target.test. 300 IN A 192.0.2.80")
			if tc.bogus {
				target.ServeTampered([]dns.RR{served}, mustRR(t, "www.target.test. 300 IN A 198.51.100.80"))
			} else {
				target.Serve(served)
			}
			// A CNAME answers every question at its owner, as a real zone
			// serves it.
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
			// The wiring middleware.Setup does in the server: the cache chases
			// an alias's target through the same pipeline.
			var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
			handler.resolver.queryer.Store(&queryer)
			cache.SetQueryer(queryer)

			// Only the target's A RRset is tampered with, so the question is
			// for A; the zone's other data, its denials included, stays sound.
			req := new(dns.Msg)
			req.SetQuestion("www.alias.test.", dns.TypeA)
			req.SetEdns0(1232, true)
			w := mock.NewWriter("udp", "127.0.0.1:0")
			ch := middleware.NewChain(handlers)
			ch.Reset(w, req)
			ch.Next(context.Background())
			if !w.Written() {
				t.Fatal("no reply")
			}
			resp := w.Msg()

			if !tc.bogus {
				if resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData || !hasType(resp, dns.TypeA) {
					t.Fatalf("%s AD=%v %v, want the validated alias and target",
						dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
				}
				return
			}
			if resp.Rcode != dns.RcodeServerFailure || resp.AuthenticatedData || len(resp.Answer) != 0 {
				t.Fatalf("%s AD=%v %v, want SERVFAIL for an alias whose target is bogus",
					dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
			}
			if !hasEDE(resp, dns.ExtendedErrorCodeDNSBogus) {
				t.Fatalf("EDE %v, want the target's DNSSEC Bogus", resp.IsEdns0())
			}
		})
	}
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
