package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// Every local failure of an alias chase echoes the client's RD: an alias to
// itself and an alias loop, served from the cache to a question that did
// not desire recursion, are SERVFAIL with RD=0, and with RD=1 for one that
// did.
func TestFailedChaseEchoesTheClientsRD(t *testing.T) {
	cname := func(owner, target string) dns.RR {
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: target,
		}
	}
	for _, tc := range []struct {
		name   string
		qname  string
		chains [][2]string
	}{
		{"an alias to itself", "self.loop.test.", [][2]string{{"self.loop.test.", "self.loop.test."}}},
		{"an alias loop", "a.loop.test.", [][2]string{{"a.loop.test.", "b.loop.test."}, {"b.loop.test.", "a.loop.test."}}},
	} {
		for _, rd := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, RD=%v", tc.name, rd), func(t *testing.T) {
				cfg := makeTestConfig()
				cfg.RateLimit = 0
				c := New(cfg)
				defer c.Stop()
				terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
					m := new(dns.Msg)
					m.SetRcode(ch.Request.Msg(), dns.RcodeServerFailure)
					_ = ch.Writer.WriteMsg(m)
					ch.Cancel()
				})
				c.SetQueryer(&internalQueryer{handlers: []middleware.Handler{c, terminal}})
				for _, link := range tc.chains {
					c.store.SetFromResponseWithCut(seamResponse(link[0], cname(link[0], link[1])), false, lease.Lease{})
				}

				q := new(dns.Msg)
				q.SetQuestion(tc.qname, dns.TypeA)
				q.RecursionDesired = rd
				q.SetEdns0(1232, false)
				w := mock.NewWriter("udp", "192.0.2.9:53000")
				ch := middleware.NewChain([]middleware.Handler{edns.New(cfg), c, terminal})
				ch.Reset(w, q)
				ch.Next(context.Background())
				resp := w.Msg()
				if resp == nil || resp.Rcode != dns.RcodeServerFailure {
					t.Fatalf("reply %v, want SERVFAIL", resp)
				}
				if resp.RecursionDesired != rd {
					t.Fatalf("reply RD = %v, want the client's %v", resp.RecursionDesired, rd)
				}
			})
		}
	}
}

// A hit for a question that does not desire recursion starts no refresh:
// answering from the cache is all it asked for, and a prefetch is upstream
// work on its behalf. The same hit with RD=1 does start one.
func TestNonRecursiveHitStartsNoPrefetch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rd       bool
		wireBorn bool
		claimed  bool
	}{
		{"RD=0, decoded", false, false, false},
		{"RD=0, wire-born", false, true, false},
		{"RD=1, decoded", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := makeTestConfig()
			cfg.RateLimit = 0
			cfg.Prefetch = 90
			c := New(cfg)
			defer c.Stop()
			e := edns.New(cfg)
			// The refresh is held until the check below has read the claim:
			// a finished one releases it.
			hold := make(chan struct{})
			defer close(hold)
			c.SetPrefetchQueryer(queryerFunc(func(context.Context, *dns.Msg) (*dns.Msg, error) {
				<-hold
				return nil, errors.New("refresh not wanted here")
			}))

			const qname = "due.example.com."
			msg := wireFastEntry(t, qname, dns.TypeA, false)
			key := CacheKey{Question: msg.Question[0]}.Hash()
			entry := NewCacheEntryWithKey(msg, 5*time.Second, 0, key)
			entry.origTTL = 100 // well past the refresh threshold
			c.positive.Set(key, entry)

			q := new(dns.Msg)
			q.SetQuestion(qname, dns.TypeA)
			q.RecursionDesired = tc.rd
			q.SetEdns0(1232, false)
			w := &captureSink{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
			ch := middleware.NewChain([]middleware.Handler{e, c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				t.Error("a cached question reached the handler below")
				ch.Cancel()
			})})
			var meta middleware.ResponseMeta
			ctx := middleware.WithResponseMeta(context.Background(), &meta)
			raw, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			req := new(middleware.Request)
			serve := func() {
				if tc.wireBorn {
					if !req.ParseWire(raw, time.Now(), nil) {
						t.Fatal("eligible query refused")
					}
					ch.ResetWire(w, req)
					ch.AllowDirectPack()
				} else {
					ch.Reset(w, q.Copy())
				}
				ch.Next(ctx)
			}
			serve()
			resp := w.Msg()
			if w.last != nil {
				resp = new(dns.Msg)
				if err := resp.Unpack(w.last); err != nil {
					t.Fatal(err)
				}
			}
			if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
				t.Fatalf("answer %v, want the cached one", resp)
			}
			if got := entry.prefetch.Load(); got != tc.claimed {
				t.Fatalf("prefetch claimed = %v, want %v", got, tc.claimed)
			}
			// Still due, and still no refresh of its own to start: an RD=0 hit
			// stays on the byte path, allocation free.
			if tc.wireBorn {
				if allocs := testing.AllocsPerRun(50, serve); allocs != 0 {
					t.Fatalf("a refresh-due RD=0 hit allocated %.2f objects per serve", allocs)
				}
			}
			if got := entry.prefetch.Load(); got != tc.claimed {
				t.Fatalf("prefetch claimed = %v, want %v", got, tc.claimed)
			}
		})
	}
}

// A question that does not desire recursion is served from the cache on
// the byte path like any other hit, RD echoed as the client sent it, and
// without allocating; a miss is declined with an EDE and never reaches
// the handler below.
func TestNonRecursiveHitTakesTheBytePath(t *testing.T) {
	const qname = "rd0.example.com."
	c, e := wireFastTestPipeline(t, wireFastEntry(t, qname, dns.TypeA, false))
	reached := false
	terminal := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		reached = true
		ch.Cancel()
	})

	wireReq := func(name string) *middleware.Request {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		q.RecursionDesired = false
		q.SetEdns0(1232, false)
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("eligible query refused")
		}
		return req
	}

	req := wireReq(qname)
	w := &captureSink{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
	ch := middleware.NewChain([]middleware.Handler{e, c, terminal})
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	serve := func() {
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(ctx)
	}
	before := wireFastServed.Value()
	serve()
	if wireFastServed.Value() == before || w.last == nil {
		t.Fatal("the RD=0 hit was not served on the byte path")
	}
	got := new(dns.Msg)
	if err := got.Unpack(w.last); err != nil {
		t.Fatal(err)
	}
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) == 0 || got.RecursionDesired {
		t.Fatalf("RD=0 hit: %s RD=%v %v, want the cached answer with RD echoed", dns.RcodeToString[got.Rcode], got.RecursionDesired, got.Answer)
	}
	if allocs := testing.AllocsPerRun(100, serve); allocs != 0 {
		t.Fatalf("an RD=0 byte-path hit allocated %.2f objects per serve", allocs)
	}

	miss := mock.NewWriter("udp", "192.0.2.9:53000")
	mch := middleware.NewChain([]middleware.Handler{e, c, terminal})
	mch.ResetWire(miss, wireReq("absent.example.com."))
	mch.Next(context.Background())
	if reached {
		t.Fatal("an RD=0 miss reached the handler below the cache")
	}
	resp := miss.Msg()
	if resp == nil || resp.Rcode != dns.RcodeServerFailure || resp.RecursionDesired {
		t.Fatalf("RD=0 miss: %v, want SERVFAIL with RD echoed", resp)
	}
	var codes []uint16
	if opt := resp.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok {
				codes = append(codes, ede.InfoCode)
			}
		}
	}
	if len(codes) != 1 || codes[0] != dns.ExtendedErrorCodeOther {
		t.Fatalf("RD=0 miss: EDE %v, want exactly EDE 0", codes)
	}
}
