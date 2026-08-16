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
	"golang.org/x/time/rate"
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
	awaitToken(t, limiter)

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

// TestReplacedEntryStillCostsOneToken pins what the permit is keyed by.
//
// A refresh can replace the entry under the same key while a query is in
// flight between the byte path and the Msg body. The entry object is a
// different one; the limiter it answers to is the same, because that is
// keyed by the entry's rate-limit key and not by its address. Keying the
// permit on the entry pointer therefore recreated the very bug it was
// added to fix, one race narrower: the same question paid twice and the
// second payment cancelled it.
//
// One question, one token — however many entry objects it passed through.
func TestReplacedEntryStillCostsOneToken(t *testing.T) {
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

	serve := func(entry *CacheEntry, spent *rate.Limiter) bool {
		w := mock.NewWriter("udp", "198.51.100.7:0")
		ch := middleware.NewChain([]middleware.Handler{c})
		ch.Reset(w, q.Copy())
		c.handleCacheHit(context.Background(), ch, entry, key, netip.Prefix{}, spent)
		return w.Written()
	}

	first := store("192.0.2.1")
	limiter := first.GetRateLimiter()
	if limiter == nil {
		t.Fatal("entry carries no rate limiter; the test would prove nothing")
	}
	awaitToken(t, limiter)

	// The byte path spends the query's token and declines.
	if !limiter.Allow() {
		t.Fatal("the limiter had no token to spend")
	}

	// A refresh replaces the entry under the same key while the query is
	// still in flight.
	second := store("192.0.2.2")
	if second == first {
		t.Skip("the store reused the entry object; this test needs a replacement")
	}
	if second.GetRateLimiter() != limiter {
		t.Fatal("the replacement answers to a different limiter; the race this " +
			"pins needs the shared one")
	}

	// The Msg body now serves the replacement. The question already paid.
	if !serve(second, limiter) {
		t.Fatal("a question that had already paid was cancelled because the entry " +
			"it was answered from had been replaced underneath it")
	}
}

// awaitToken waits until the shared limiter has a token, so a test that
// needs to spend exactly one is not defeated by the previous run of the
// same test: the limiters are process-global and keyed by rate and entry
// key, which is precisely how they are shared in production.
func awaitToken(t *testing.T, limiter *rate.Limiter) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for limiter.Tokens() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the shared limiter never refilled")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
