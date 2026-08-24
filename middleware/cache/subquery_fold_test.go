package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// TestSubqueryPositiveHitDoesNotBindRequest reproduces the served-TTL
// collapse: resolver subqueries (DNSKEY and DS lookups) consult the cache
// through GetWithContext, and a positive hit used to fold its own remaining
// lifetime into the shared request meta. The client answer then stamped that
// bound as its cutUntil, so a fresh 3600-second answer was served with
// whatever happened to remain on the oldest key consulted during the walk.
// A positive consult is a validation input, not part of the answer's
// lineage; it must leave the request tree unbounded.
func TestSubqueryPositiveHitDoesNotBindRequest(t *testing.T) {
	s := newTestStore(t)
	const name = "dnskey.example."
	s.SetFromResponse(newTestSuccessResp(name), false, time.Time{})

	meta := &middleware.ResponseMeta{}
	ctx := middleware.WithResponseMeta(context.Background(), meta)

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	if _, ok := s.GetWithContext(ctx, req); !ok {
		t.Fatal("expected a positive hit")
	}
	if cut, _ := meta.Cut(); !cut.IsZero() {
		t.Fatalf("positive consult bound the request tree to %v", cut)
	}
}

// TestSubqueryNegativeHitStillBindsRequest pins the other side of the line:
// a cached denial consulted mid-resolution — a DS NODATA holding a
// delegation insecure — is validation state, and whatever is assembled from
// it must not outlive the proof (GHSA-mqfw-f48p-2vc8).
func TestSubqueryNegativeHitStillBindsRequest(t *testing.T) {
	s := newTestStore(t)
	const name = "insecure.example."

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeDS)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 60,
		Retry:   60,
		Expire:  60,
		Minttl:  300,
	}}
	s.SetFromResponse(resp, false, time.Time{})

	meta := &middleware.ResponseMeta{}
	ctx := middleware.WithResponseMeta(context.Background(), meta)

	if _, ok := s.GetWithContext(ctx, req); !ok {
		t.Fatal("expected a NODATA hit")
	}
	if cut, _ := meta.Cut(); cut.IsZero() {
		t.Fatal("denial consult no longer bounds the request tree")
	}
}
