package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
)

// A type the resolver has no name for is resolved like any other (RFC 3597):
// its data comes back, validated, through the cache as the server wires it.
func TestUnknownTypeIsResolvedTransparently(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("signed.")
	zone.Serve(mustRR(t, `opaque.signed. 300 IN TYPE65534 \# 4 01020304`))

	cfg := net.Config()
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	cache := answercache.New(cfg)
	handlers := []middleware.Handler{cache, handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	cache.SetQueryer(queryer)

	for _, pass := range []string{"resolved", "cached"} {
		req := new(dns.Msg)
		req.SetQuestion("opaque.signed.", 65534)
		req.SetEdns0(1232, true)
		w := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain(handlers)
		ch.Reset(w, req)
		ch.Next(context.Background())
		if !w.Written() {
			t.Fatalf("%s: no reply to a question for an unknown type", pass)
		}
		resp := w.Msg()
		if resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData || !answersType(resp, 65534) {
			t.Fatalf("%s: %s AD=%v %v, want the validated opaque record",
				pass, dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
		}
	}
}

func answersType(m *dns.Msg, t uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}
