package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/edns"
)

// TestANYIsDeclinedAheadOfEveryForwardingPath pins the ANY policy to the
// server rather than to the resolver: a whole-server forwarder and a forward
// zone both used to hand the question on before the resolver's NOTIMP could
// apply, so the same query was declined in one mode and forwarded in the
// other. It is declined on every path now, before anything is decoded for
// the questions that are handed on, with the client's DO echoed. Zone
// transfers and NXNAME are declined the same way.
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
		for _, d := range declinedCases {
			t.Run(tc.name+"/"+dns.TypeToString[d.qtype], func(t *testing.T) {
				cfg := makeTestConfig()
				tc.configure(cfg)
				h := New(cfg)
				handedOn := false
				next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
					handedOn = true
					ch.Cancel()
				})

				req := new(dns.Msg)
				req.SetQuestion("any.example.", d.qtype)
				req.RecursionDesired = true
				req.SetEdns0(1232, true)
				w := mock.NewWriter("udp", "127.0.0.1:0")
				chain := middleware.NewChain([]middleware.Handler{h, next})
				chain.Reset(w, req)
				chain.Next(context.Background())

				if handedOn {
					t.Fatal("the question was handed on instead of declined")
				}
				if !w.Written() {
					t.Fatal("no response written")
				}
				resp := w.Msg()
				wantDeclined(t, resp, d)
				if opt := resp.IsEdns0(); opt == nil || !opt.Do() {
					t.Fatal("the client's DO was not echoed")
				}
				if len(resp.Question) != 1 || resp.Question[0].Qtype != d.qtype {
					t.Fatalf("question not echoed: %v", resp.Question)
				}
			})
		}
	}
}

// From the server's entry, through the EDNS layer, the cache and the
// resolver: every declined question is answered by the policy, wire-born
// and decoded, again and again, and never reaches an authority. A cached
// FORMERR or REFUSED would come back as a replayed SERVFAIL.
func TestDeclinedQuestionsFromTheServersEntry(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("signed.")
	zone.Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
	cfg := net.Config()
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	cache := answercache.New(cfg)
	handlers := []middleware.Handler{cache, handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	cache.SetQueryer(queryer)
	client := append([]middleware.Handler{edns.New(cfg)}, handlers...)

	for _, d := range declinedCases {
		for _, wireBorn := range []bool{true, false, true, false} {
			q := new(dns.Msg)
			q.SetQuestion("www.signed.", d.qtype)
			q.SetEdns0(1232, false)
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
				t.Fatalf("%s wire-born=%v: no reply", dns.TypeToString[d.qtype], wireBorn)
			}
			wantDeclined(t, w.Msg(), d)
		}
		if n := zone.asked("www.signed.", d.qtype); n != 0 {
			t.Fatalf("%s reached the authority %d times", dns.TypeToString[d.qtype], n)
		}
	}
}

// declinedCases are the questions the server answers by its own policy.
var declinedCases = []struct {
	qtype uint16
	rcode int
	ede   uint16 // 0: none
}{
	{dns.TypeANY, dns.RcodeNotImplemented, dns.ExtendedErrorCodeNotSupported},
	{dns.TypeAXFR, dns.RcodeRefused, 0},
	{dns.TypeIXFR, dns.RcodeRefused, 0},
	{dns.TypeNXNAME, dns.RcodeFormatError, dns.ExtendedErrorCodeInvalidQueryType},
}

// wantDeclined checks a policy answer's rcode and its one EDE, or none.
func wantDeclined(t *testing.T, resp *dns.Msg, d struct {
	qtype uint16
	rcode int
	ede   uint16
}) {
	t.Helper()
	if resp.Rcode != d.rcode {
		t.Fatalf("answered %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[d.rcode])
	}
	var edes []uint16
	if opt := resp.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_EDE); ok {
				edes = append(edes, e.InfoCode)
			}
		}
	}
	switch {
	case d.ede == 0 && len(edes) != 0:
		t.Fatalf("EDE %v on a reply that carries none", edes)
	case d.ede != 0 && (len(edes) != 1 || edes[0] != d.ede):
		t.Fatalf("EDE %v, want exactly %d", edes, d.ede)
	}
}
