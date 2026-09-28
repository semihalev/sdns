package cache

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// An answer is pruned once nothing can serve it again: past its TTL
// without serve-stale; with it, past its delegation lease or
// serve_stale_max_ttl. A fresh one, one serve-stale may still answer from,
// and one whose refresh is under way stay.
func TestUnservable(t *testing.T) {
	for _, tc := range []struct {
		name           string
		serveStale     bool
		maxStale       time.Duration
		staleFor       time.Duration // negative: still fresh for that long
		leaseRemaining time.Duration
		refreshing     bool
		want           bool
	}{
		{name: "fresh", staleFor: -time.Minute, want: false},
		{name: "fresh, its lease gone", staleFor: -time.Minute, leaseRemaining: -time.Second, want: true},
		{name: "expired", staleFor: time.Second, want: true},
		{name: "expired, refresh under way", staleFor: time.Second, refreshing: true, want: false},
		{name: "stale, servable", serveStale: true, maxStale: time.Hour, staleFor: time.Minute, leaseRemaining: time.Hour, want: false},
		{name: "stale, past serve_stale_max_ttl", serveStale: true, maxStale: time.Hour, staleFor: 2 * time.Hour, want: true},
		{name: "stale, lease gone", serveStale: true, maxStale: time.Hour, staleFor: time.Minute, leaseRemaining: -time.Second, want: true},
		{name: "stale, no bound but eviction", serveStale: true, staleFor: 48 * time.Hour, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A zero serve_stale_max_ttl leaves the lease, and eviction, as
			// the only bounds.
			cfg := &config.Config{CacheSize: 1024, ServeStale: tc.serveStale}
			cfg.ServeStaleMaxTTL.Duration = tc.maxStale
			c := New(cfg)
			defer c.Stop()
			req := new(dns.Msg)
			req.SetQuestion("prune.example.", dns.TypeA)
			e := seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, tc.staleFor, tc.leaseRemaining)
			e.prefetch.Store(tc.refreshing)
			if got := c.store.unservable(e, time.Now()); got != tc.want {
				t.Fatalf("unservable = %v, want %v", got, tc.want)
			}
		})
	}
}

// A pass removes the expired answers and keeps the fresh ones.
func TestPrunePass(t *testing.T) {
	c := New(&config.Config{CacheSize: 4096})
	defer c.Stop()
	for i, name := range []string{"a.example.", "b.example.", "c.example.", "d.example."} {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		staleFor := time.Minute
		if i%2 == 0 {
			staleFor = -time.Minute
		}
		seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, staleFor, 0)
	}
	var stopped atomic.Bool
	if removed := c.store.prunePass(&stopped, 0); removed != 2 {
		t.Fatalf("removed %d, want the 2 expired", removed)
	}
	if n := c.store.PositiveLen(); n != 2 {
		t.Fatalf("%d answers left, want the 2 fresh", n)
	}
}
