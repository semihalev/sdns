package resolver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
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
