//go:build !race

package middleware

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// TestPipelineQueryerQueryAllocationBudget gates what one sub-query costs.
//
// This is the shape production runs, a request through the whole pipeline,
// establishing the request-tree state a recursive query needs, so it is
// where an accidental extra object shows up, and where counting one scope in
// isolation would miss it.
//
// The number is a budget, not a law: raise it deliberately, with the reason,
// never to make a run pass.
//
// Excluded under the race detector, which adds allocations of its own (11
// against 9 here) and would make the budget measure the tooling.
func TestPipelineQueryerQueryAllocationBudget(t *testing.T) {
	const budget = 9

	rec := &recordingHandler{name: "rec", rcode: dns.RcodeSuccess}
	Reset()
	t.Cleanup(Reset)
	DefaultRegistry.Register(rec.Name(), func(_ *config.Config) Handler { return rec })
	Setup(&config.Config{})

	q := NewPipelineQueryer(GlobalPipeline())
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ctx := context.Background()

	allocs := testing.AllocsPerRun(200, func() {
		if _, err := q.Query(ctx, req); err != nil {
			t.Fatalf("query: %v", err)
		}
	})
	if allocs > budget {
		t.Fatalf("a sub-query cost %.0f allocations, budget is %d", allocs, budget)
	}
	t.Logf("sub-query allocations: %.0f of %d", allocs, budget)
}
