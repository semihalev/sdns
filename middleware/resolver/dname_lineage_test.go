package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// dnameLineageQueryer answers the DNAME target leg. It records the bound the
// leg was resolved under, and publishes one of its own.
type dnameLineageQueryer struct {
	observed time.Time
	publish  time.Time
}

func (q *dnameLineageQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	meta := middleware.ResponseMetaFrom(ctx)
	q.observed = meta.CutUntil()
	meta.BoundCutFor(q.publish, 42)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.CheckingDisabled = true
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{192, 0, 2, 33},
	}}
	return resp, nil
}

// TestDNAMETargetResolvesUnderItsOwnLineage pins both directions of the rule
// for the DNAME leg, which is cached under the target's own name.
//
// The target must not be resolved under the outer DNAME's bound — a nearly
// expired alias would otherwise store a freshly resolved target with the
// alias's seconds. And the outer response must inherit the target's bound,
// because after the splice the target's records are what the client is
// served.
func TestDNAMETargetResolvesUnderItsOwnLineage(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("host.alias.test.", dns.TypeA)
	req.CheckingDisabled = true

	outer := new(dns.Msg)
	outer.SetReply(req)
	outer.CheckingDisabled = true
	outer.Answer = []dns.RR{&dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   "alias.test.",
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    120,
		},
		Target: "target.test.",
	}}

	// The outer response is bound long, the target short, so the direction of
	// the merge is visible: only the target's bound can win.
	outerDeadline := time.Now().Add(10 * time.Minute)
	targetDeadline := time.Now().Add(30 * time.Second)

	queryer := &dnameLineageQueryer{publish: targetDeadline}
	var queryerInterface middleware.Queryer = queryer
	r := new(Resolver)
	r.queryer.Store(&queryerInterface)

	var meta middleware.ResponseMeta
	meta.BoundCutFor(outerDeadline, 7)
	ctx := middleware.WithResponseMeta(context.Background(), &meta)

	if _, err := r.answer(ctx, req, outer, nil, "alias.test."); err != nil {
		t.Fatalf("merge DNAME target: %v", err)
	}

	if !queryer.observed.IsZero() {
		t.Fatalf("the target leg was resolved under the outer response's "+
			"bound of %v; it is cached under its own name and must carry "+
			"its own lineage", queryer.observed)
	}

	got, key := meta.Cut()
	if !got.Equal(targetDeadline) || key != 42 {
		t.Fatalf("outer bound = (%v, %d) after the splice, want the target's "+
			"(%v, 42): the records the client is served came from it",
			got, key, targetDeadline)
	}
}
