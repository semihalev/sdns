package ratelimit

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func Test_RateLimit(t *testing.T) {
	cfg := new(config.Config)
	cfg.ClientRateLimit = 1

	// The registry is process-wide, so a second run in the same process,
	// go test -count=2, say, would otherwise panic on re-registration.
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("ratelimit", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	r := middleware.Get("ratelimit").(*RateLimit)

	if !reflect.DeepEqual("ratelimit", r.Name()) {
		t.Errorf("r.Name() = %v, want %v", r.Name(), "ratelimit")
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, true)

	passes := 0
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passes++
		ch.Cancel()
	})
	serve := func(proto, addr string) {
		ch := middleware.NewChain([]middleware.Handler{r, next})
		ch.Reset(mock.NewWriter(proto, addr), req)
		ch.Next(context.Background())
	}

	// No address and loopback are never limited.
	for range 3 {
		serve("udp", "")
		serve("udp", "127.0.0.1:0")
	}
	if passes != 6 {
		t.Fatalf("passes = %d, want 6: no address and loopback bypass the limiter", passes)
	}

	serve("udp", "10.0.0.1:0")
	serve("udp", "10.0.0.1:0")
	if passes != 7 {
		t.Fatalf("passes = %d, want 7: the second query over a rate of 1 is dropped", passes)
	}

	r.rate = 0
	serve("udp", "10.0.0.1:0")
	if passes != 8 {
		t.Fatalf("passes = %d, want 8: a rate of 0 limits nothing", passes)
	}
}
