package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestANYIsDeclinedAheadOfEveryForwardingPath pins the ANY policy to the
// server rather than to the resolver: a whole-server forwarder and a forward
// zone both used to hand the question on before the resolver's NOTIMP could
// apply, so the same query was declined in one mode and forwarded in the
// other. It is declined on every path now, before anything is decoded for
// the questions that are handed on, with the client's DO echoed.
func TestANYIsDeclinedAheadOfEveryForwardingPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*config.Config)
	}{
		{"no forwarding", func(*config.Config) {}},
		{"a whole-server forwarder", func(cfg *config.Config) { cfg.ForwarderServers = []string{"192.0.2.53:53"} }},
		{"a forward zone covering the name", func(cfg *config.Config) {
			cfg.ForwardZones = []config.ForwardZoneConfig{{Name: "example.", Servers: []string{"192.0.2.53:53"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := makeTestConfig()
			tc.configure(cfg)
			h := New(cfg)
			handedOn := false
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				handedOn = true
				ch.Cancel()
			})

			req := new(dns.Msg)
			req.SetQuestion("any.example.", dns.TypeANY)
			req.RecursionDesired = true
			req.SetEdns0(1232, true)
			w := mock.NewWriter("udp", "127.0.0.1:0")
			chain := middleware.NewChain([]middleware.Handler{h, next})
			chain.Reset(w, req)
			chain.Next(context.Background())

			if handedOn {
				t.Fatal("the ANY question was handed on instead of declined")
			}
			if !w.Written() {
				t.Fatal("no response written")
			}
			resp := w.Msg()
			if resp.Rcode != dns.RcodeNotImplemented {
				t.Fatalf("answered %s, want NOTIMP", dns.RcodeToString[resp.Rcode])
			}
			if opt := resp.IsEdns0(); opt == nil || !opt.Do() {
				t.Fatal("the client's DO was not echoed")
			}
			if len(resp.Question) != 1 || resp.Question[0].Qtype != dns.TypeANY {
				t.Fatalf("question not echoed: %v", resp.Question)
			}
		})
	}
}
