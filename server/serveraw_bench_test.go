package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/defaults"
)

// benchAnswerStub is the terminal in place of the resolver: the warm-up
// miss materializes and answers a cacheable record; the measured loop
// never reaches it. A class test installs its own respond hook.
type benchAnswerStub struct {
	respond func(req *dns.Msg) *dns.Msg
}

func (benchAnswerStub) Name() string { return "bench-answer-stub" }

func (s benchAnswerStub) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	_ = ctx
	var resp *dns.Msg
	if s.respond != nil {
		resp = s.respond(req)
	} else {
		resp = new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		rr, err := dns.NewRR(req.Question[0].Name + " 300 IN A 192.0.2.77")
		if err == nil {
			resp.Answer = []dns.RR{rr}
		}
	}
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

// newHitChainServer builds a server over the default hit-path chain with
// the resolver replaced by the terminal stub.
func newHitChainServer(tb testing.TB) *Server {
	return newHitChainServerWith(tb, nil)
}

func newHitChainServerWith(tb testing.TB, respond func(req *dns.Msg) *dns.Msg) *Server {
	tb.Helper()
	middleware.Reset()
	tb.Cleanup(middleware.Reset)
	// The real chain, up to the resolver — which the stub below stands in
	// for. Taking it from the generated list rather than repeating it here
	// is the difference between benchmarking what production runs and
	// benchmarking a list that was accurate when it was written: this one
	// had already lost dnstap, accesslog, hostsfile, dns64 and failover.
	defaults.RegisterUpTo("resolver")
	middleware.Register("bench-answer-stub", func(*config.Config) middleware.Handler { return benchAnswerStub{respond: respond} })

	cfg := &config.Config{ //nolint:gosec // G101 — the cookie secret is a test fixture, not a credential
		Bind:         "127.0.0.1:0",
		Expire:       600,
		CacheSize:    10240,
		CookieSecret: "6c6f6f6b61686172646c6f6f6b6168617264",
	}
	cfg.QueryTimeout.Duration = 10 * time.Second
	middleware.Setup(cfg)
	return New(cfg)
}

// TestServeRawWarmHitWithEDNS pins the warm exact-entry hit for an EDNS
// client end to end: NOERROR, the cached answer, and a well-formed reply
// OPT. This is the shape the wire fast path serves in production — a
// regression here (the nil-OPT wireOPTLen crash was one) hides behind
// recovery's SERVFAIL otherwise.
func TestServeRawWarmHitWithEDNS(t *testing.T) {
	s := newHitChainServer(t)

	m := new(dns.Msg)
	m.SetQuestion("warm.zero.test.", dns.TypeA)
	m.SetEdns0(1232, true)
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 21), Port: 4242}}
	for i := 0; i < 3; i++ {
		job.wrote = job.wrote[:0]
		if !s.ServeRaw(job, raw, time.Now()) {
			t.Fatalf("serve %d not handled", i)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(job.wrote); err != nil {
			t.Fatalf("serve %d reply unpack: %v", i, err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("serve %d rcode %s, want NOERROR", i, dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 1 || resp.Answer[0].Header().Name != "warm.zero.test." {
			t.Fatalf("serve %d answer %v", i, resp.Answer)
		}
		opt := resp.IsEdns0()
		if opt == nil || opt.Version() != 0 {
			t.Fatalf("serve %d reply OPT malformed: %v", i, opt)
		}
	}
}

// BenchmarkServeRawWireHit measures the warm exact-entry hit through the
// strict ingress against the default hit-path chain (resolver replaced by
// a terminal stub the warm loop never reaches). Precise enough to
// attribute single allocations with -memprofile. Run per flavor: with and
// without a client OPT.
func BenchmarkServeRawWireHit(b *testing.B) {
	for _, withEDNS := range []bool{false, true} {
		name := "noopt"
		if withEDNS {
			name = "edns"
		}
		b.Run(name, func(b *testing.B) {
			s := newHitChainServer(b)

			m := new(dns.Msg)
			m.SetQuestion("bench.zero.test.", dns.TypeA)
			if withEDNS {
				m.SetEdns0(1232, true)
			}
			raw, err := m.Pack()
			if err != nil {
				b.Fatalf("pack: %v", err)
			}

			job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 4242}}
			// Warm: the first serve misses and stores, the second must hit.
			for i := 0; i < 2; i++ {
				job.wrote = job.wrote[:0]
				if !s.ServeRaw(job, raw, time.Now()) {
					b.Fatalf("warm serve %d not handled", i)
				}
				if len(job.wrote) == 0 {
					b.Fatalf("warm serve %d wrote nothing", i)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.ServeRaw(job, raw, time.Now()) {
					b.Fatal("hit serve not handled")
				}
			}
		})
	}
}
