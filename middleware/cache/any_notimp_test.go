package cache

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestNotImplementedIsNeitherCachedNorAFailure pins the cache's view of the
// ANY policy answer. NOTIMP used to classify as a resolution failure, so the
// first ANY question was answered NOTIMP by the policy and the second, for
// the same name, SERVFAIL from the failure cache. Both are NOTIMP now, each
// from the policy, and nothing about the name is remembered.
func TestNotImplementedIsNeitherCachedNorAFailure(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	policy := 0
	handler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		policy++
		_ = ch.Writer.WriteMsg(SetRcodeForTest(ch.Request.Msg(), dns.RcodeNotImplemented))
		ch.Cancel()
	})

	ask := func() *dns.Msg {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion("any.example.", dns.TypeANY)
		req.RecursionDesired = true
		w := mock.NewWriter("udp", "127.0.0.1:0")
		chain := middleware.NewChain([]middleware.Handler{c, handler})
		chain.Reset(w, req)
		chain.Next(context.Background())
		if !w.Written() {
			t.Fatal("no response written")
		}
		return w.Msg()
	}

	for i := 1; i <= 2; i++ {
		if got := ask().Rcode; got != dns.RcodeNotImplemented {
			t.Fatalf("question %d answered %s, want NOTIMP", i, dns.RcodeToString[got])
		}
	}
	if policy != 2 {
		t.Fatalf("the policy answered %d times, want 2: nothing about the name may be remembered", policy)
	}
	if c.store.NXDomainCutLen() != 0 || c.store.positive.Len() != 0 {
		t.Fatal("a NOTIMP answer was stored")
	}
}

// SetRcodeForTest builds a reply carrying rcode, the way the resolver's
// policy answers do.
func SetRcodeForTest(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	return m
}
