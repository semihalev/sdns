package resolver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/failover"
)

// A validation failure reaches the client as the SERVFAIL it is, through the
// real failover and resolver on a wire-born request, whatever shape the bogus
// data takes: a signature over the answer that does not verify, a referral
// whose DS does not verify, a DNAME whose target does not. The fallback,
// which would answer every question, is never asked.
func TestValidationFailureIsNotFailedOver(t *testing.T) {
	net := newHermeticNet(t)
	net.Delegate("badsig.test.").ServeTampered(
		[]dns.RR{mustRR(t, "www.badsig.test. 300 IN A 192.0.2.70")},
		mustRR(t, "www.badsig.test. 300 IN A 198.51.100.70"))
	net.DelegateTamperedDS("badds.test.").Serve(mustRR(t, "www.badds.test. 300 IN A 192.0.2.90"))
	net.Delegate("target.test.").ServeTampered(
		[]dns.RR{mustRR(t, "www.target.test. 300 IN A 192.0.2.80")},
		mustRR(t, "www.target.test. 300 IN A 198.51.100.80"))
	alias := net.Delegate("alias.test.")
	dname := mustRR(t, "alias.test. 300 IN DNAME target.test.")
	alias.server.serve("www.alias.test.", dns.TypeA,
		dname, alias.key.sign(t, []dns.RR{dname}),
		mustRR(t, "www.alias.test. 300 IN CNAME www.target.test."))

	var asked int64
	fallback, stop := startMockAuth(t, &asked, func(q dns.Question) *dns.Msg {
		m := new(dns.Msg)
		m.Answer = []dns.RR{mustRR(t, q.Name+" 300 IN A 203.0.113.1")}
		return m
	})
	defer stop()
	cfg := net.Config()
	cfg.FallbackServers = []string{fallback}
	handlers := []middleware.Handler{failover.New(cfg), net.handlerWithConfig(cfg)}

	for _, name := range []string{"www.badsig.test.", "www.badds.test.", "www.alias.test."} {
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeA)
		msg.SetEdns0(1232, true)
		raw, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("query refused")
		}
		before := atomic.LoadInt64(&asked)
		writer := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain(handlers)
		ch.ResetWire(writer, req)
		ch.Next(context.Background())

		if got := writer.Msg(); got == nil || got.Rcode != dns.RcodeServerFailure {
			t.Fatalf("%s: response %v, want the validator's SERVFAIL", name, got)
		}
		if n := atomic.LoadInt64(&asked) - before; n != 0 {
			t.Fatalf("%s: the fallback was asked %d times", name, n)
		}
	}
}

// pipelineQueryer runs a resolver's internal sub-queries through a whole
// pipeline, as production does, so a target is answered from the cache
// when the cache holds it.
type pipelineQueryer struct{ handlers []middleware.Handler }

func (q pipelineQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain(q.handlers)
	ch.Reset(writer, req)
	ch.Next(ctx)
	if !writer.Written() {
		return nil, middleware.ErrNoResponse
	}
	return writer.Msg(), nil
}

// A validation failure the RFC 9520 failure cache holds is replayed as the
// verdict it was. A DNAME resolved after its target's bogus answer was
// cached composes its SERVFAIL from that replay, and failover must leave it
// alone exactly as it did the target.
func TestCachedValidationFailureIsNotFailedOver(t *testing.T) {
	net := newHermeticNet(t)
	target := net.Delegate("target.test.")
	target.ServeTampered(
		[]dns.RR{mustRR(t, "www.target.test. 300 IN A 192.0.2.80")},
		mustRR(t, "www.target.test. 300 IN A 198.51.100.80"))
	alias := net.Delegate("alias.test.")
	dname := mustRR(t, "alias.test. 300 IN DNAME target.test.")
	alias.server.serve("www.alias.test.", dns.TypeA,
		dname, alias.key.sign(t, []dns.RR{dname}),
		mustRR(t, "www.alias.test. 300 IN CNAME www.target.test."))

	var asked int64
	fallback, stop := startMockAuth(t, &asked, func(q dns.Question) *dns.Msg {
		m := new(dns.Msg)
		m.Answer = []dns.RR{mustRR(t, q.Name+" 300 IN A 203.0.113.1")}
		return m
	})
	defer stop()
	cfg := net.Config()
	cfg.FallbackServers = []string{fallback}
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	handlers := []middleware.Handler{answercache.New(cfg), failover.New(cfg), handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)

	ask := func(name string) *dns.Msg {
		t.Helper()
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeA)
		msg.SetEdns0(1232, true)
		raw, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("query refused")
		}
		writer := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain(handlers)
		ch.ResetWire(writer, req)
		ch.Next(context.Background())
		return writer.Msg()
	}

	if got := ask("www.target.test."); got == nil || got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("target: %v, want SERVFAIL", got)
	}
	targetAsked := target.asked("www.target.test.", dns.TypeA)

	got := ask("www.alias.test.")
	if got == nil || got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("alias: %v, want the target's SERVFAIL", got)
	}
	if n := target.asked("www.target.test.", dns.TypeA); n != targetAsked {
		t.Fatalf("the target was asked again (%d, was %d): the alias did not meet the cached failure", n, targetAsked)
	}
	if n := atomic.LoadInt64(&asked); n != 0 {
		t.Fatalf("the fallback was asked %d times", n)
	}
}
