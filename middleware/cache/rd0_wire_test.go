package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

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
