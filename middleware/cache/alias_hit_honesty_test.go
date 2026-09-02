package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestAliasHitAppliesTheOutgoingChecksToTheChasedTarget pins the hit path
// against the miss path for an alias whose target is not cached. The chase
// resolves the target through the internal sub-query, whose own write skips
// the outgoing checks as every internal write does, so the merged records
// reached the client raw: the target at its full TTL, with AD, and with a
// lapsed signature in the answer. The hit now applies what a miss applies,
// AD withdrawn when a signature has lapsed and TTLs bounded by the merged
// records.
func TestAliasHitAppliesTheOutgoingChecksToTheChasedTarget(t *testing.T) {
	const alias, target = "a.rev.example.", "b.rev.example."
	now := time.Now()

	for _, tc := range []struct {
		name      string
		expiresIn time.Duration
		wantAD    bool
		maxTTL    uint32
		wantRRSIG bool
	}{
		{"target signed for two more seconds", 2 * time.Second, true, 2, true},
		{"target signature lapsed an hour ago", -time.Hour, false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, Expire: 600})
			defer c.Stop()

			aliasResp := new(dns.Msg)
			aliasResp.SetQuestion(alias, dns.TypeA)
			aliasResp.Response = true
			aliasResp.AuthenticatedData = true
			aliasResp.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: alias, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
				Target: target,
			}}
			c.store.SetFromResponse(aliasResp, false, time.Time{})

			targetHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				resp := new(dns.Msg)
				resp.SetReply(ch.Request.Msg())
				resp.AuthenticatedData = true
				resp.Answer = []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{192, 0, 2, 7}},
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: target, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeA, Algorithm: 8, Labels: 3, OrigTtl: 3600, KeyTag: 1,
						SignerName: "rev.example.", Signature: "MTIzNDU2Nzg5MGFiY2RlZg==",
						Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
						Expiration: uint32(now.Add(tc.expiresIn).Unix()),   //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
					},
				}
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
			})
			c.SetQueryer(&internalQueryer{handlers: []middleware.Handler{c, targetHandler}})

			req := new(dns.Msg)
			req.SetQuestion(alias, dns.TypeA)
			req.RecursionDesired = true
			w := mock.NewWriter("udp", "127.0.0.1:0")
			chain := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				t.Fatal("the alias hit missed the cache")
			})})
			chain.Reset(w, req)
			chain.Next(context.Background())
			if !w.Written() {
				t.Fatal("no response written")
			}
			served := w.Msg()

			if served.AuthenticatedData != tc.wantAD {
				t.Errorf("AD = %v, want %v", served.AuthenticatedData, tc.wantAD)
			}
			var a *dns.A
			for _, rr := range served.Answer {
				if r, ok := rr.(*dns.A); ok {
					a = r
				}
			}
			if a == nil {
				t.Fatalf("the chased target is missing from the answer: %v", served.Answer)
			}
			if a.Hdr.Ttl > tc.maxTTL {
				t.Errorf("the chased target served with TTL %d, want at most %d: bounded by its own signature", a.Hdr.Ttl, tc.maxTTL)
			}
			for _, rr := range served.Answer {
				if rr.Header().Ttl > tc.maxTTL {
					t.Errorf("%s served with TTL %d, want at most %d", rr.Header().String(), rr.Header().Ttl, tc.maxTTL)
				}
			}
		})
	}
}
