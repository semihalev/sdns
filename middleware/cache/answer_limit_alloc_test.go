//go:build !race

package cache

import (
	"context"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// Charging an answer to its limit is a compare-and-swap on the entry: a
// hit within its rate stays on the byte path and allocates nothing.
func TestLimitedHitWithinItsRateAllocatesNothing(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1 << 30
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	storeAnswer(t, c, "within.example. 300 IN A 192.0.2.1")
	req, _ := wireTestRequest(t, "within.example.", dns.TypeA, false)
	w := &captureSink{Writer: mock.NewWriter("udp", "203.0.113.9:53000")}
	ch := middleware.NewChain([]middleware.Handler{c})
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	serve := func() {
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(ctx)
	}

	before := wireFastServed.Value()
	serve()
	if wireFastServed.Value() == before {
		t.Fatal("the hit was not served on the byte path")
	}
	if allocs := testing.AllocsPerRun(100, serve); allocs != 0 {
		t.Fatalf("a hit within its answer's rate allocated %.1f objects", allocs)
	}
}

// The reply a flood draws is the truncated one, so it is what a flood
// costs per packet: on a transport with the byte path it is written into
// the lease from the request's own bytes and allocates nothing, the same
// as the answer it stands in for.
func TestTruncatedReplyOnTheWireAllocatesNothing(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	storeAnswer(t, c, "wire-tc.example. 300 IN A 192.0.2.1")
	req, _ := wireTestRequest(t, "wire-tc.example.", dns.TypeA, false)
	w := &captureSink{Writer: mock.NewWriter("udp", "203.0.113.9:53000")}
	ch := middleware.NewChain([]middleware.Handler{c})
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	serve := func() {
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(ctx)
	}

	serve() // spends the bucket's one token on the answer
	if allocs := testing.AllocsPerRun(100, serve); allocs != 0 {
		t.Fatalf("a query over its answer's limit allocated %.1f objects", allocs)
	}

	m := new(dns.Msg)
	if err := m.Unpack(w.last); err != nil {
		t.Fatal(err)
	}
	if !m.Truncated || !m.Response || !m.RecursionAvailable || len(m.Answer) != 0 {
		t.Fatalf("reply = %v, want an empty truncated response", m)
	}
	if m.Id != req.ID() || len(m.Question) != 1 || m.Question[0].Name != "wire-tc.example." ||
		m.Question[0].Qtype != dns.TypeA || m.Question[0].Qclass != dns.ClassINET {
		t.Fatalf("reply does not echo the query's ID and question: %v", m)
	}
}
