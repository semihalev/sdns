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

// DelegateUnsupportedDS creates a child whose DS at the parent is validly
// signed but, after alter, names nothing this validator verifies: RFC 6840
// §5.2 treats the child as insecure. signed says whether the child signs
// its data at all.
func (n *hermeticNet) DelegateUnsupportedDS(zone string, signed bool, alter func(*dns.DS)) *hermeticZone {
	n.tb.Helper()
	z := n.delegate(zone, signed, true, false)
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

var dsVariants = []struct {
	name  string
	alter func(*dns.DS)
	ede   uint16 // 0: the DS is usable
}{
	{"usable DS", func(*dns.DS) {}, 0},
	{"unsupported algorithm", func(ds *dns.DS) { ds.Algorithm = dns.ED448 }, dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm},
	{"unsupported digest", func(ds *dns.DS) { ds.DigestType = dns.GOST94 }, dns.ExtendedErrorCodeUnsupportedDSDigestType},
}

// edeClient is the server's chain over a hermetic namespace: the EDNS
// layer, the cache, the resolver.
type edeClient struct {
	t      *testing.T
	client []middleware.Handler
	cache  *answercache.Cache
}

func newEDEClient(t *testing.T, net *hermeticNet) *edeClient {
	t.Helper()
	cfg := net.Config()
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	cache := answercache.New(cfg)
	cache.SetDNSSECCryptoLimiter(handler.DNSSECCryptoLimiter())
	handlers := []middleware.Handler{cache, handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	cache.SetQueryer(queryer)
	return &edeClient{t: t, client: append([]middleware.Handler{edns.New(cfg)}, handlers...), cache: cache}
}

func (c *edeClient) ask(name string, qtype uint16, wireBorn, cd bool) *dns.Msg {
	c.t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.SetEdns0(1232, true)
	q.CheckingDisabled = cd
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain(c.client)
	if wireBorn {
		raw, err := q.Pack()
		if err != nil {
			c.t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			c.t.Fatal("eligible query refused by ParseWire")
		}
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
	} else {
		ch.Reset(w, q)
	}
	ch.Next(context.Background())
	if !w.Written() {
		c.t.Fatal("no reply")
	}
	return w.Msg()
}

func edeCodes(m *dns.Msg) []uint16 {
	var codes []uint16
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_EDE); ok {
				codes = append(codes, e.InfoCode)
			}
		}
	}
	return codes
}

// passes asks each question resolved, then from the cache wire-born, then
// from the cache decoded, and hands every reply to check.
func (c *edeClient) passes(questions []dns.Question, check func(step string, q dns.Question, resp *dns.Msg)) {
	c.t.Helper()
	for _, q := range questions {
		for _, pass := range []struct {
			step     string
			wireBorn bool
		}{
			{"resolved", false},
			{"cached, wire-born", true},
			{"cached, decoded", false},
		} {
			check(pass.step, q, c.ask(q.Name, q.Qtype, pass.wireBorn, false))
		}
	}
}

// answers are the questions every case asks: a positive answer, NODATA and
// NXDOMAIN. NXDOMAIN goes last: a fixture's denial is one NSEC spanning
// the whole zone, and once validated, aggressive use (RFC 8198) would deny
// the NODATA name with it.
func answers(zone string) []dns.Question {
	return []dns.Question{
		{Name: "www." + zone, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "www." + zone, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		{Name: "missing." + zone, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
}

func wantRcode(q dns.Question) int {
	if q.Name == "missing.signed." || q.Name == "missing.bare." {
		return dns.RcodeNameError
	}
	return dns.RcodeSuccess
}

// The EDE goes first on a copy of the reply's OPT: the one a reply carries
// is often the request's own, which later exchanges still send, and the
// cache keeps a reply's first EDE only. A reply with no OPT gets one.
func TestWithEDELeavesTheSharedOPTAlone(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("www.signed.", dns.TypeA)
	req.SetEdns0(1232, true)
	shared := req.IsEdns0()
	upstream := &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeOther}
	shared.Option = append(make([]dns.EDNS0, 0, 4), upstream)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Extra = req.Extra
	withEDE(resp, dns.ExtendedErrorCodeUnsupportedDSDigestType)

	if len(shared.Option) != 1 || len(req.Extra) != 1 || req.Extra[0] != shared {
		t.Fatalf("the request's OPT changed: %v", req.Extra)
	}
	if spare := shared.Option[:2]; spare[1] != nil {
		t.Fatalf("the EDE landed in the request's option array: %v", spare[1])
	}
	if got := edeCodes(resp); len(got) != 2 || got[0] != dns.ExtendedErrorCodeUnsupportedDSDigestType {
		t.Fatalf("reply EDEs %v, want the local reason first", got)
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
// answer, NXDOMAIN and NODATA alike, resolved and then served from the
// cache, wire-born and decoded, through the EDNS layer, the cache and the
// resolver; whether the zone signs its data or not. A zone with a usable
// DS is validated and says nothing; unsigned under a usable DS, it is
// bogus.
func TestInsecureByUnsupportedDSSaysWhy(t *testing.T) {
	for _, signed := range []bool{true, false} {
		for _, v := range dsVariants {
			name := v.name + ", signed"
			if !signed {
				name = v.name + ", unsigned"
			}
			t.Run(name, func(t *testing.T) {
				net := newHermeticNet(t)
				zone := net.DelegateUnsupportedDS("signed.", signed, v.alter)
				www := mustRR(t, "www.signed. 300 IN A 192.0.2.45")
				if signed {
					zone.Serve(www)
				} else {
					zone.ServeUnsigned(www)
				}
				c := newEDEClient(t, net)
				c.passes(answers("signed."), func(step string, q dns.Question, resp *dns.Msg) {
					t.Helper()
					if v.ede == 0 && !signed {
						if resp.Rcode != dns.RcodeServerFailure {
							t.Fatalf("%s %s %s: %s, want unsigned data under a usable DS refused",
								q.Name, dns.TypeToString[q.Qtype], step, dns.RcodeToString[resp.Rcode])
						}
						return
					}
					if resp.Rcode != wantRcode(q) {
						t.Fatalf("%s %s %s: %s, want %s", q.Name, dns.TypeToString[q.Qtype], step,
							dns.RcodeToString[resp.Rcode], dns.RcodeToString[wantRcode(q)])
					}
					if resp.AuthenticatedData != (v.ede == 0) {
						t.Fatalf("%s %s %s: AD=%v, want %v", q.Name, dns.TypeToString[q.Qtype], step,
							resp.AuthenticatedData, v.ede == 0)
					}
					got := edeCodes(resp)
					switch {
					case v.ede == 0 && len(got) != 0:
						t.Fatalf("%s %s %s: EDE %v on a validated answer", q.Name, dns.TypeToString[q.Qtype], step, got)
					case v.ede != 0 && (len(got) != 1 || got[0] != v.ede):
						t.Fatalf("%s %s %s: EDE %v, want exactly %d", q.Name, dns.TypeToString[q.Qtype], step, got, v.ede)
					}
				})
			})
		}
	}
}

// The reason is the validator's own, and nothing else produces it: a zone
// with no DS is insecure through its signed denial, and a CD=1 client
// asked for no validation.
func TestInsecureByUnsupportedDSControls(t *testing.T) {
	net := newHermeticNet(t)
	net.DelegateInsecure("bare.").ServeUnsigned(mustRR(t, "www.bare. 300 IN A 192.0.2.46"))
	net.DelegateUnsupportedDS("signed.", true, func(ds *dns.DS) { ds.DigestType = dns.GOST94 }).
		Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
	c := newEDEClient(t, net)

	c.passes(answers("bare."), func(step string, q dns.Question, resp *dns.Msg) {
		t.Helper()
		if resp.Rcode != wantRcode(q) || len(edeCodes(resp)) != 0 {
			t.Fatalf("%s %s %s: %s EDE %v, want %s and no EDE for a zone without a DS",
				q.Name, dns.TypeToString[q.Qtype], step, dns.RcodeToString[resp.Rcode], edeCodes(resp),
				dns.RcodeToString[wantRcode(q)])
		}
	})
	for _, q := range answers("signed.") {
		if resp := c.ask(q.Name, q.Qtype, false, true); len(edeCodes(resp)) != 0 {
			t.Fatalf("%s %s CD=1: EDE %v, want none without validation", q.Name, dns.TypeToString[q.Qtype], edeCodes(resp))
		}
	}
}

// An authority's own EDE rides the reply too, but the cache keeps a reply's
// first EDE only: the local reason goes first, so the cached answer still
// says why it is insecure.
func TestInsecureReasonOutranksAnAuthoritysEDE(t *testing.T) {
	for _, v := range dsVariants[1:] {
		t.Run(v.name, func(t *testing.T) {
			net := newHermeticNet(t)
			zone := net.DelegateUnsupportedDS("signed.", true, v.alter)
			zone.Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
			zone.server.mu.Lock()
			zone.server.shapeReply = func(m *dns.Msg) {
				m.SetEdns0(1232, true)
				m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeOther}}
			}
			zone.server.mu.Unlock()
			c := newEDEClient(t, net)
			c.passes(answers("signed."), func(step string, q dns.Question, resp *dns.Msg) {
				t.Helper()
				if got := edeCodes(resp); len(got) == 0 || got[0] != v.ede {
					t.Fatalf("%s %s %s: EDE %v, want %d first", q.Name, dns.TypeToString[q.Qtype], step, got, v.ede)
				}
			})
		})
	}
}

// The same insecure data reached through an alias keeps its explanation:
// a signed alias, CNAME or DNAME, to a target in a zone whose DS is
// unusable answers with the target's records, no AD, and the target's
// reason, resolved and from the cache.
func TestInsecureReasonCrossesAnAlias(t *testing.T) {
	for _, v := range dsVariants[1:] {
		t.Run(v.name, func(t *testing.T) {
			net := newHermeticNet(t)
			net.DelegateUnsupportedDS("target.test.", true, v.alter).
				Serve(mustRR(t, "www.target.test. 300 IN A 192.0.2.80"))
			alias := net.Delegate("alias.test.")
			cname := mustRR(t, "www.alias.test. 300 IN CNAME www.target.test.")
			alias.server.serve("www.alias.test.", dns.TypeA, cname, alias.key.sign(t, []dns.RR{cname}))
			dnameZone := net.Delegate("dname.test.")
			dname := mustRR(t, "dname.test. 300 IN DNAME target.test.")
			dnameZone.server.serve("www.dname.test.", dns.TypeA,
				dname, dnameZone.key.sign(t, []dns.RR{dname}),
				mustRR(t, "www.dname.test. 300 IN CNAME www.target.test."))
			c := newEDEClient(t, net)

			questions := []dns.Question{
				{Name: "www.alias.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: "www.dname.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			}
			c.passes(questions, func(step string, q dns.Question, resp *dns.Msg) {
				t.Helper()
				hasA := false
				for _, rr := range resp.Answer {
					if a, ok := rr.(*dns.A); ok && a.Hdr.Name == "www.target.test." {
						hasA = true
					}
				}
				if resp.Rcode != dns.RcodeSuccess || !hasA || resp.AuthenticatedData {
					t.Fatalf("%s %s: %s AD=%v %v, want the target's address without AD",
						q.Name, step, dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
				}
				if got := edeCodes(resp); len(got) != 1 || got[0] != v.ede {
					t.Fatalf("%s %s: EDE %v, want exactly %d", q.Name, step, got, v.ede)
				}
			})
		})
	}
}
