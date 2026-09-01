package ratelimit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

const wireTestCookie = "aabbccdd11223344" // 8 raw bytes in the hex form miekg packs

func wireRequest(t *testing.T, cookie string) *middleware.Request {
	t.Helper()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(4096, true)
	if cookie != "" {
		opt := q.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: cookie,
		})
	}
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused by ParseWire")
	}
	return req
}

// TestRateLimitWireStaysUndecoded pins the fast path: a wire-born request
// with no cookie, and one whose cookie verifies, both pass the limiter
// without being materialized.
func TestRateLimitWireStaysUndecoded(t *testing.T) {
	r := New(&config.Config{ClientRateLimit: 100, CookieSecret: "secret"})

	var passed, sawUndecoded bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		sawUndecoded = ch.Request.Undecoded()
		ch.Cancel()
	})

	// No cookie at all.
	req := wireRequest(t, "")
	w := mock.NewWriter("udp", "10.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if !passed || !sawUndecoded {
		t.Fatalf("no-cookie: passed=%v undecoded=%v, want both true", passed, sawUndecoded)
	}

	// A fresh cookie against an empty limiter cache verifies and passes.
	passed, sawUndecoded = false, false
	req = wireRequest(t, wireTestCookie)
	w = mock.NewWriter("udp", "10.0.0.2:0")
	ch = middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if !passed || !sawUndecoded {
		t.Fatalf("fresh cookie: passed=%v undecoded=%v, want both true", passed, sawUndecoded)
	}
}

// TestRateLimitWireBadCookie drives the one wire branch that decodes: a
// stale cookie over UDP earns BADCOOKIE carrying the refreshed server
// cookie, exactly as the decoded body produces it.
func TestRateLimitWireBadCookie(t *testing.T) {
	r := New(&config.Config{ClientRateLimit: 100, CookieSecret: "secret"})

	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		ch.Cancel()
	})

	// First serve stores the server cookie for this client.
	req := wireRequest(t, wireTestCookie)
	w := mock.NewWriter("udp", "10.0.0.3:0")
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if w.Written() {
		t.Fatal("first serve should pass through, not answer")
	}

	// Second serve echoes the same bare client cookie; the limiter now
	// holds client+server, so the echo no longer matches.
	req = wireRequest(t, wireTestCookie)
	w = mock.NewWriter("udp", "10.0.0.3:0")
	ch = middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	if !w.Written() {
		t.Fatal("stale cookie over UDP should be answered")
	}
	if w.Rcode() != dns.RcodeBadCookie {
		t.Fatalf("rcode = %v, want BADCOOKIE", w.Rcode())
	}

	want := dnsutil.GenerateServerCookie("secret", "10.0.0.3", wireTestCookie)
	opt := w.Msg().IsEdns0()
	if opt == nil {
		t.Fatal("BADCOOKIE reply has no OPT")
	}
	var got string
	for _, option := range opt.Option {
		if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
			got = cookie.Cookie
		}
	}
	if got != want {
		t.Fatalf("reply cookie = %q, want %q", got, want)
	}
}

// TestRateLimitWireTCPMismatchFallsThrough pins the spoof-proof-transport
// leg: a stale cookie over TCP takes the plain limiter, continues down the
// chain undecoded, and still refreshes the stored server cookie afterward.
func TestRateLimitWireTCPMismatchFallsThrough(t *testing.T) {
	r := New(&config.Config{ClientRateLimit: 100, CookieSecret: "secret"})

	var passed, sawUndecoded bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		sawUndecoded = ch.Request.Undecoded()
		ch.Cancel()
	})

	serve := func() *mock.Writer {
		req := wireRequest(t, wireTestCookie)
		w := mock.NewWriter("tcp", "10.0.0.5:0")
		ch := middleware.NewChain([]middleware.Handler{r, next})
		ch.ResetWire(w, req)
		ch.Next(context.Background())
		return w
	}

	serve() // primes the stored server cookie; the bare echo now mismatches

	l := r.getLimiter(net.ParseIP("10.0.0.5"))
	stored := l.cookie.Load().(string)
	if stored == "" {
		t.Fatal("first serve stored no cookie")
	}

	passed, sawUndecoded = false, false
	if w := serve(); w.Written() {
		t.Fatal("TCP mismatch must not be answered by the limiter")
	}
	if !passed || !sawUndecoded {
		t.Fatalf("TCP mismatch: passed=%v undecoded=%v, want both true", passed, sawUndecoded)
	}
	if refreshed := l.cookie.Load().(string); refreshed == "" {
		t.Fatal("post-Next cookie store was dropped")
	}
}

// TestRateLimitWireFullEchoMatch pins the recovery leg of the BADCOOKIE
// cycle: a client echoing the stored full cookie, client half plus server
// half, the 40-byte maximum, verifies and passes undecoded.
func TestRateLimitWireFullEchoMatch(t *testing.T) {
	r := New(&config.Config{ClientRateLimit: 100, CookieSecret: "secret"})

	var passed, sawUndecoded bool
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		sawUndecoded = ch.Request.Undecoded()
		ch.Cancel()
	})

	req := wireRequest(t, wireTestCookie)
	w := mock.NewWriter("udp", "10.0.0.6:0")
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())

	stored := r.getLimiter(net.ParseIP("10.0.0.6")).cookie.Load().(string)
	if len(stored) != 80 {
		t.Fatalf("stored cookie length = %d hex chars, want 80 (8+32 bytes)", len(stored))
	}

	passed, sawUndecoded = false, false
	req = wireRequest(t, stored)
	w = mock.NewWriter("udp", "10.0.0.6:0")
	ch = middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())

	if w.Written() {
		t.Fatal("a verifying full echo must not be answered by the limiter")
	}
	if !passed || !sawUndecoded {
		t.Fatalf("full echo: passed=%v undecoded=%v, want both true", passed, sawUndecoded)
	}
}

// TestRateLimitWireOverLimit checks the plain limiter still bites on the
// wire path: with a rate of 1, the second cookieless query is dropped
// without a reply.
func TestRateLimitWireOverLimit(t *testing.T) {
	r := New(&config.Config{ClientRateLimit: 1, CookieSecret: "secret"})

	var passes int
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passes++
		ch.Cancel()
	})

	for i := 0; i < 3; i++ {
		req := wireRequest(t, "")
		w := mock.NewWriter("udp", "10.0.0.4:0")
		ch := middleware.NewChain([]middleware.Handler{r, next})
		ch.ResetWire(w, req)
		ch.Next(context.Background())
		if w.Written() {
			t.Fatal("over-limit drop must not write a reply")
		}
	}
	if passes >= 3 {
		t.Fatalf("passes = %d, want the limiter to drop some of 3", passes)
	}
}
