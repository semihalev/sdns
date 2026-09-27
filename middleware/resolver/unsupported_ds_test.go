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

// DelegateUnsupportedDS creates a signed child whose DS at the parent is
// validly signed but, after alter, names nothing this validator verifies:
// RFC 6840 §5.2 treats the child as insecure.
func (n *hermeticNet) DelegateUnsupportedDS(zone string, alter func(*dns.DS)) *hermeticZone {
	n.tb.Helper()
	z := n.delegate(zone, true, true, false)
	ds := dns.Copy(z.ds[0]).(*dns.DS)
	alter(ds)
	sig := n.rootKey.sign(n.tb, []dns.RR{ds})
	n.root.serve(z.name, dns.TypeDS, ds, sig)
	n.root.mu.Lock()
	referral := n.root.children[z.name]
	referral.ns = []dns.RR{referral.ns[0], ds, sig}
	n.root.mu.Unlock()
	z.ds = []dns.RR{ds}
	return z
}

// The EDE goes on a copy of the reply's OPT: the one a reply carries is
// often the request's own, which later exchanges still send. A reply with
// no OPT gets one.
func TestWithEDELeavesTheSharedOPTAlone(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("www.signed.", dns.TypeA)
	req.SetEdns0(1232, true)
	shared := req.IsEdns0()
	shared.Option = append(make([]dns.EDNS0, 0, 4), &dns.EDNS0_NSID{Code: dns.EDNS0NSID})

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Extra = req.Extra
	withEDE(resp, dns.ExtendedErrorCodeUnsupportedDSDigestType)

	if len(shared.Option) != 1 || len(req.Extra) != 1 || req.Extra[0] != shared {
		t.Fatalf("the request's OPT changed: %v", req.Extra)
	}
	opt := resp.IsEdns0()
	if opt == shared || len(opt.Option) != 2 {
		t.Fatalf("reply OPT %v, want a copy carrying the EDE", opt)
	}
	// The spare capacity of the shared option list must not be written.
	if spare := shared.Option[:2]; spare[1] != nil {
		t.Fatalf("the EDE landed in the request's option array: %v", spare[1])
	}

	bare := new(dns.Msg)
	bare.SetReply(req)
	withEDE(bare, dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm)
	if o := bare.IsEdns0(); o == nil || len(o.Option) != 1 {
		t.Fatalf("a reply without an OPT did not get one: %v", bare.Extra)
	}
}

// An answer left insecure because its zone's only DS names an algorithm or
// a digest this validator does not verify says why (RFC 8914 §4.2, §4.3):
// Unsupported DNSKEY Algorithm, or Unsupported DS Digest Type. A positive
// answer and a denial alike, resolved and then served from the cache,
// wire-born and decoded, through the EDNS layer, the cache and the
// resolver. A zone with a usable DS is validated and says nothing.
func TestInsecureByUnsupportedDSSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*dns.DS)
		ede   uint16 // 0: validated, no EDE
	}{
		{"usable DS", func(*dns.DS) {}, 0},
		{"unsupported algorithm", func(ds *dns.DS) { ds.Algorithm = dns.ED448 }, dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm},
		{"unsupported digest", func(ds *dns.DS) { ds.DigestType = dns.GOST94 }, dns.ExtendedErrorCodeUnsupportedDSDigestType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := newHermeticNet(t)
			zone := net.DelegateUnsupportedDS("signed.", tc.alter)
			zone.Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
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

			ask := func(name string, wireBorn bool) *dns.Msg {
				t.Helper()
				q := new(dns.Msg)
				q.SetQuestion(name, dns.TypeA)
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
					t.Fatal("no reply")
				}
				return w.Msg()
			}

			for _, c := range []struct {
				name  string
				rcode int
			}{
				{"www.signed.", dns.RcodeSuccess},
				{"missing.signed.", dns.RcodeNameError},
			} {
				for _, pass := range []struct {
					step     string
					wireBorn bool
				}{
					{"resolved", false},
					{"cached, wire-born", true},
					{"cached, decoded", false},
				} {
					resp := ask(c.name, pass.wireBorn)
					if resp.Rcode != c.rcode {
						t.Fatalf("%s %s: %s, want %s", c.name, pass.step,
							dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.rcode])
					}
					if resp.AuthenticatedData != (tc.ede == 0) {
						t.Fatalf("%s %s: AD=%v, want %v", c.name, pass.step, resp.AuthenticatedData, tc.ede == 0)
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
					case tc.ede == 0 && len(edes) != 0:
						t.Fatalf("%s %s: EDE %v on a validated answer", c.name, pass.step, edes)
					case tc.ede != 0 && (len(edes) != 1 || edes[0] != tc.ede):
						t.Fatalf("%s %s: EDE %v, want exactly %d", c.name, pass.step, edes, tc.ede)
					}
				}
			}
		})
	}
}
