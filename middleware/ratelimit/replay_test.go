package ratelimit

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// The replay pass finishes a query whose token was already consumed on
// the inline pass; running the limiter again would bill one question
// twice. Ten replay passes must leave the bucket untouched — if any of
// them consumed, the normal pass at the end would find it empty.
func TestRateLimitReplayPassesThrough(t *testing.T) {
	cfg := &config.Config{ClientRateLimit: 1, CookieSecret: "6c6f6f6b61686172646c6f6f6b6168617264"} //nolint:gosec // test fixture
	r := New(cfg)

	q := new(dns.Msg)
	q.SetQuestion("replay.example.", dns.TypeA)

	reached := 0
	next := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		reached++
		ch.Cancel()
	})

	for range 10 {
		ch := middleware.NewChain([]middleware.Handler{next})
		ch.Reset(mock.NewWriter("udp", "203.0.113.61:5353"), q)
		ch.SetReplay()
		r.ServeDNS(context.Background(), ch)
	}
	if reached != 10 {
		t.Fatalf("replay passes reached the next handler %d times, want 10", reached)
	}

	// The bucket is still full: a normal first pass gets through.
	ch := middleware.NewChain([]middleware.Handler{next})
	ch.Reset(mock.NewWriter("udp", "203.0.113.61:5353"), q)
	r.ServeDNS(context.Background(), ch)
	if reached != 11 {
		t.Fatal("normal pass was limited: a replay pass consumed a token it must not touch")
	}
}
