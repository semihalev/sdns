package cache

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// The refusal of a non-recursive question echoes its RD=0 (RFC 1035
// §4.1.1): the reply does not claim a recursion the client never asked for.
func TestNonRecursiveRefusalEchoesRD(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer c.Stop()
	reached := false
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		reached = true
		ch.Cancel()
	})

	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeA)
	req.RecursionDesired = false
	w := mock.NewWriter("udp", "192.0.2.9:53000")
	ch := middleware.NewChain([]middleware.Handler{c, next})
	ch.Reset(w, req)
	ch.Next(context.Background())

	if reached || !w.Written() {
		t.Fatalf("reached=%v written=%v, want the cache to answer it", reached, w.Written())
	}
	resp := w.Msg()
	if resp.Rcode != dns.RcodeServerFailure || resp.RecursionDesired {
		t.Fatalf("%s RD=%v, want SERVFAIL echoing RD=0", dns.RcodeToString[resp.Rcode], resp.RecursionDesired)
	}
}
