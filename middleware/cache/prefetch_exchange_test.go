package cache

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// TestPrefetchExchangeUnwired covers the nil-prefetchQueryer branch
// in Cache.prefetchExchange: production wiring (middleware.Setup's
// auto-wire) always installs one, but tests and partial setups need
// the errQueryerNotWired sentinel rather than a nil deref.
func TestPrefetchExchangeUnwired(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 60})
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	_, err := c.prefetchExchange(context.Background(), req)
	if !errors.Is(err, errQueryerNotWired) {
		t.Fatalf("prefetchExchange err = %v, want errQueryerNotWired", err)
	}
}

// stubPrefetchQueryer returns a canned response for the prefetch
// path exercise below.
type stubPrefetchQueryer struct{ resp *dns.Msg }

func (q *stubPrefetchQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return q.resp, nil
}

// TestPrefetchExchangeWired covers the happy-path: installed queryer
// is called and its response bubbles out.
func TestPrefetchExchangeWired(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 60})
	defer c.Stop()

	canned := newTestSuccessResp("example.com.")
	c.SetPrefetchQueryer(&stubPrefetchQueryer{resp: canned})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	got, err := c.prefetchExchange(context.Background(), req)
	if err != nil {
		t.Fatalf("prefetchExchange: %v", err)
	}
	if got != canned {
		t.Fatalf("prefetchExchange returned unexpected msg")
	}
}
