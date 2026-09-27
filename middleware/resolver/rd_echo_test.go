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

// The same, from the server's entry: through the EDNS layer, the cache and
// the resolver, for a wire-born request and a decoded one. ANY is answered
// before the resolution starts, and must echo RD all the same.
func TestServedRepliesEchoTheClientsRD(t *testing.T) {
	net := newHermeticNet(t)
	net.Delegate("signed.").Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
	cfg := net.Config()
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	cache := answercache.New(cfg)
	handlers := []middleware.Handler{cache, handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	cache.SetQueryer(queryer)
	client := append([]middleware.Handler{edns.New(cfg)}, handlers...)

	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
		rd    bool
		rcode int
	}{
		{"ANY, RD=0", "www.signed.", dns.TypeANY, false, dns.RcodeNotImplemented},
		{"ANY, RD=1", "www.signed.", dns.TypeANY, true, dns.RcodeNotImplemented},
		{"resolved, RD=1", "www.signed.", dns.TypeA, true, dns.RcodeSuccess},
		{"non-recursive question, cached, RD=0", "www.signed.", dns.TypeA, false, dns.RcodeSuccess},
		{"non-recursive question, not cached, RD=0", "missing.signed.", dns.TypeA, false, dns.RcodeServerFailure},
		{"root, RD=0", ".", dns.TypeNS, false, dns.RcodeSuccess},
	} {
		for _, wireBorn := range []bool{false, true} {
			name := tc.name + "/decoded"
			if wireBorn {
				name = tc.name + "/wire-born"
			}
			t.Run(name, func(t *testing.T) {
				q := new(dns.Msg)
				q.SetQuestion(tc.qname, tc.qtype)
				q.SetEdns0(1232, true)
				q.RecursionDesired = tc.rd
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
				} else {
					ch.Reset(w, q)
				}
				ch.Next(context.Background())
				if !w.Written() {
					t.Fatal("no reply")
				}
				resp := w.Msg()
				if resp.Rcode != tc.rcode {
					t.Fatalf("rcode %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
				}
				if resp.RecursionDesired != tc.rd {
					t.Fatalf("reply RD = %v, want the client's %v", resp.RecursionDesired, tc.rd)
				}
			})
		}
	}
}

// Every reply echoes the client's RD (RFC 1035 §4.1.1), whatever the
// resolution did with the request on the way, and the request holds the
// client's RD again once the handler returns.
func TestResolverRepliesEchoTheClientsRD(t *testing.T) {
	net := newHermeticNet(t)
	net.Delegate("signed.").Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
	handler := net.Handler()

	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
		rd    bool
		rcode int
	}{
		{"resolved, RD=1", "www.signed.", dns.TypeA, true, dns.RcodeSuccess},
		{"root, RD=0", ".", dns.TypeNS, false, dns.RcodeSuccess},
		{"ANY policy answer, RD=0", "www.signed.", dns.TypeANY, false, dns.RcodeNotImplemented},
		{"non-recursive question, RD=0", "www.signed.", dns.TypeA, false, dns.RcodeServerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, tc.qtype)
			req.SetEdns0(1232, true)
			req.RecursionDesired = tc.rd
			resp := handler.handle(context.Background(), req)
			if resp.Rcode != tc.rcode {
				t.Fatalf("rcode %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
			if resp.RecursionDesired != tc.rd {
				t.Fatalf("reply RD = %v, want the client's %v", resp.RecursionDesired, tc.rd)
			}
			if req.RecursionDesired != tc.rd {
				t.Fatalf("request RD = %v after the handler, want the client's %v back", req.RecursionDesired, tc.rd)
			}
		})
	}
}
