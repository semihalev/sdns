package cache

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestWireDeclineDoesNotSpendTheLimiterTwice pins one question to one
// token.
//
// The byte path takes the entry's rate-limit permit before it knows
// whether it can answer, and several things below that point hand the
// request to the Msg body instead — a prefetch-due entry, a transport
// without the wire lease, a body the capability cannot express, a lease
// too small to commit. The Msg body checks the same limiter. At a limit
// of one the second check finds the bucket empty and cancels a hit the
// client had already paid for: the query is answered with silence, and
// nothing says why.
//
// A prefetch-due entry is the shape used here because it is the one an
// operator meets first: it fires on every hot name, once per TTL.
func TestWireDeclineDoesNotSpendTheLimiterTwice(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1
	cfg.Prefetch = 10
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	q := new(dns.Msg)
	q.SetQuestion("permit.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Answer = []dns.RR{makeRR("permit.example. 300 IN A 192.0.2.9")}
	c.store.SetFromResponse(resp, false, time.Time{})

	key := CacheKey{Question: q.Question[0], CD: false}.Hash()
	entry, ok := c.store.LookupByKey(key)
	if !ok {
		t.Fatal("entry not stored")
	}
	limiter := entry.GetRateLimiter()
	if limiter == nil {
		t.Fatal("entry carries no rate limiter; the test would prove nothing")
	}

	// Age it into the refresh window: 29s left of 300 is inside the 10%
	// threshold, so the byte path declines and the Msg body serves.
	entry.stored = time.Now().Add(-271 * time.Second)
	if !entry.ShouldPrefetch(int(cfg.Prefetch)) {
		t.Fatal("entry is not prefetch-due; the decline this pins never happens")
	}

	req, _ := wireTestRequest(t, "permit.example.", dns.TypeA, false)
	w := mock.NewWriter("udp", "198.51.100.7:0")
	ch := middleware.NewChain([]middleware.Handler{c})
	ch.ResetWire(w, req)
	ch.Next(context.Background())

	if !w.Written() {
		t.Fatal("the hit was cancelled: the byte path spent the query's only " +
			"token and then declined, so the Msg body found the bucket empty " +
			"and dropped an answer the client was entitled to")
	}
	if got := answerA(w.Msg()); got != "192.0.2.9" {
		t.Fatalf("answer = %q, want 192.0.2.9", got)
	}
}

// TestReplacedEntryPaysItsOwnLimiter pins the other half of the rule: the
// permit is remembered against the entry it was spent on, not against the
// query.
//
// An entry replaced under the same key between the byte path and the Msg
// body is a different entry sharing the same limiter. Carrying the permit
// to it would let the replacement serve free of charge, so the identity
// has to be the entry and not "a permit was taken somewhere".
func TestReplacedEntryPaysItsOwnLimiter(t *testing.T) {
	cfg := makeTestConfig()
	cfg.RateLimit = 1
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	q := new(dns.Msg)
	q.SetQuestion("replaced.example.", dns.TypeA)
	key := CacheKey{Question: q.Question[0], CD: false}.Hash()

	store := func(addr string) *CacheEntry {
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = []dns.RR{makeRR("replaced.example. 300 IN A " + addr)}
		c.store.SetFromResponse(resp, false, time.Time{})
		entry, ok := c.store.LookupByKey(key)
		if !ok {
			t.Fatal("entry not stored")
		}
		return entry
	}

	serve := func(entry, spent *CacheEntry) bool {
		w := mock.NewWriter("udp", "198.51.100.7:0")
		ch := middleware.NewChain([]middleware.Handler{c})
		ch.Reset(w, q.Copy())
		c.handleCacheHit(context.Background(), ch, entry, key, netip.Prefix{}, spent)
		return w.Written()
	}

	first := store("192.0.2.1")
	if !serve(first, nil) {
		t.Fatal("the first query spent the only token and should have been served")
	}

	second := store("192.0.2.2")
	if second == first {
		t.Skip("the store reused the entry object; this test needs a replacement")
	}
	if serve(second, first) {
		t.Fatal("a replaced entry was served on the permit spent for the entry it " +
			"replaced; the limiter they share was never charged")
	}
}
