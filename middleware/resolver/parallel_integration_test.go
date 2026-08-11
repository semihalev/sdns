package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// The parallel lookup paths used to be exercised against www.github.com. and
// www.google.com., which made them depend on the network and on those zones
// staying put. They run against a signed loopback namespace now, so the
// answers are known and the assertions can be exact.

func TestParallelLookupIntegration(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("parallel.test.")
	zone.Serve(
		mustRR(t, "www.parallel.test. 300 IN A 192.0.2.71"),
		mustRR(t, "www.parallel.test. 300 IN A 192.0.2.72"),
	)
	// Two nameservers, one of which never replies, so the lookup has to
	// pick a winner rather than simply talk to the only address it has.
	zone.AddSilentAuthority(net)

	// Hold the answering nameserver until the silent one has been asked.
	// Without this the fast server answers first and the second address is
	// never tried, so the test would pass against a resolver that queries
	// one server at a time — removing this line makes it fail.
	zone.HoldUntil(func() bool {
		return zone.silentAsked("www.parallel.test.", dns.TypeA) > 0
	}, 3*time.Second)

	cfg := net.Config()
	cfg.QnameMinLevel = 0 // resolve the full name at each step
	// A per-server budget long enough that waiting one out is unmistakable.
	cfg.Timeout.Duration = 2 * time.Second
	r := net.handlerWithConfig(cfg).resolver

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion("www.parallel.test.", dns.TypeA)
	req.SetEdns0(4096, true)

	start := time.Now()
	resp, err := r.Resolve(ctx, req, r.rootServers, true, 30, 0, false, nil)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Both assertions together are what a serial implementation cannot
	// satisfy. The answering nameserver was held until the silent one had
	// been contacted, so an answer arriving at all means the two were in
	// flight together; and it arrived well inside the budget, so nothing
	// waited the silent one out first.
	assert.Greater(t, zone.silentAsked("www.parallel.test.", dns.TypeA), 0,
		"the second nameserver was never contacted, so nothing was raced")
	assert.Less(t, elapsed, cfg.Timeout.Duration,
		"the answer arrived only after the silent nameserver's budget expired")

	addresses := []string{}
	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			addresses = append(addresses, a.A.String())
		}
	}
	assert.ElementsMatch(t, []string{"192.0.2.71", "192.0.2.72"}, addresses)
}

func TestParallelLookupIPv6(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("v6.test.")
	zone.Serve(mustRR(t, "www.v6.test. 300 IN AAAA 2001:db8::71"))

	cfg := net.Config()
	cfg.IPv6Access = true
	r := net.handlerWithConfig(cfg).resolver

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion("www.v6.test.", dns.TypeAAAA)
	req.SetEdns0(4096, true)

	resp, err := r.Resolve(ctx, req, r.rootServers, true, 30, 0, false, nil)

	// The previous version logged whatever happened and asserted nothing,
	// so an AAAA lookup that quietly stopped working looked like a pass.
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	// A signed answer carries its RRSIG alongside the data, so the records
	// are selected by type rather than counted.
	addresses := []string{}
	for _, answer := range resp.Answer {
		if aaaa, ok := answer.(*dns.AAAA); ok {
			addresses = append(addresses, aaaa.AAAA.String())
		}
	}
	assert.Equal(t, []string{"2001:db8::71"}, addresses)
}

func BenchmarkParallelLookup(b *testing.B) {
	net := newHermeticNet(b)
	zone := net.Delegate("bench.test.")
	answer, err := dns.NewRR("www.bench.test. 300 IN A 192.0.2.73")
	if err != nil {
		b.Fatalf("NewRR: %v", err)
	}
	zone.Serve(answer)

	r := net.Resolver()
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		req := new(dns.Msg)
		req.SetQuestion("www.bench.test.", dns.TypeA)
		req.SetEdns0(4096, true)

		if _, err := r.Resolve(ctx, req, r.rootServers, true, 30, 0, false, nil); err != nil {
			b.Fatalf("resolve: %v", err)
		}
	}
}
