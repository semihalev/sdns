package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/edns"
)

// From the server's entry, through the EDNS layer, the cache and the
// resolver: a bogus answer fails with DNSSEC Bogus, and the failure cache
// says the same afterwards, to a wire-born request and a decoded one alike,
// without asking the zone again.
func TestCachedValidationFailureKeepsItsEDE(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("signed.")
	zone.ServeTampered(
		[]dns.RR{mustRR(t, "www.signed. 300 IN A 192.0.2.45")},
		mustRR(t, "www.signed. 300 IN A 198.51.100.45"))
	cfg := net.Config()
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	cache := answercache.New(cfg)
	cache.SetDNSSECCryptoLimiter(handler.DNSSECCryptoLimiter())
	handlers := []middleware.Handler{cache, handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	cache.SetQueryer(queryer)
	client := append([]middleware.Handler{edns.New(cfg)}, handlers...)

	ask := func(step string, wireBorn bool) {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion("www.signed.", dns.TypeA)
		q.SetEdns0(1232, true)
		w := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain(client)
		if wireBorn {
			raw, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			req := new(middleware.Request)
			if !req.ParseWire(raw, time.Now(), nil) {
				t.Fatal("eligible query refused by ParseWire")
			}
			ch.ResetWire(w, req)
			ch.AllowDirectPack()
		} else {
			ch.Reset(w, q)
		}
		ch.Next(context.Background())
		if !w.Written() {
			t.Fatalf("%s: no reply", step)
		}
		resp := w.Msg()
		if resp.Rcode != dns.RcodeServerFailure || resp.AuthenticatedData || len(resp.Answer) != 0 {
			t.Fatalf("%s: %s AD=%v %v, want SERVFAIL for bogus data",
				step, dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
		}
		n := 0
		if opt := resp.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_EDE); ok {
					n++
				}
			}
		}
		if n != 1 || !hasEDE(resp, dns.ExtendedErrorCodeDNSBogus) {
			t.Fatalf("%s: want exactly one EDE, DNSSEC Bogus, got:\n%v", step, resp)
		}
	}

	ask("resolved", false)
	asked := zone.asked("www.signed.", dns.TypeA)
	if asked == 0 {
		t.Fatal("the zone was never asked; the failure is not the resolver's")
	}
	ask("cached, wire-born", true)
	ask("cached, decoded", false)
	if again := zone.asked("www.signed.", dns.TypeA); again != asked {
		t.Fatalf("the zone was asked %d more times, want the failure cache's answers", again-asked)
	}
}
