package cache

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/cache"
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
		// denial, "nxdomain" or "nodata", stores that denial in place of
		// an answer.
		denial string
		want   bool
	}{
		{name: "fresh", staleFor: -time.Minute, want: false},
		{name: "fresh, its lease gone", staleFor: -time.Minute, leaseRemaining: -time.Second, want: true},
		{name: "expired", staleFor: time.Second, want: true},
		{name: "expired, refresh under way", staleFor: time.Second, refreshing: true, want: false},
		{name: "stale, servable", serveStale: true, maxStale: time.Hour, staleFor: time.Minute, leaseRemaining: time.Hour, want: false},
		{name: "stale, past serve_stale_max_ttl", serveStale: true, maxStale: time.Hour, staleFor: 2 * time.Hour, want: true},
		{name: "stale, lease gone", serveStale: true, maxStale: time.Hour, staleFor: time.Minute, leaseRemaining: -time.Second, want: true},
		{name: "stale, no bound but eviction", serveStale: true, staleFor: 48 * time.Hour, want: false},
		{name: "stale NXDOMAIN, no bound but eviction", serveStale: true, staleFor: time.Minute, denial: "nxdomain", want: true},
		{name: "stale NODATA, no bound but eviction", serveStale: true, staleFor: time.Minute, denial: "nodata", want: true},
		{name: "fresh NXDOMAIN", serveStale: true, staleFor: -time.Minute, denial: "nxdomain", want: false},
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
			resp := staleTestAnswer(req, "192.0.2.1")
			if tc.denial != "" {
				rcode := dns.RcodeSuccess
				if tc.denial == "nxdomain" {
					rcode = dns.RcodeNameError
				}
				resp = new(dns.Msg)
				resp.SetRcode(req, rcode)
				resp.Ns = []dns.RR{&dns.SOA{
					Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns.example.", Mbox: "host.example.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
				}}
			}
			e := seedStaleEntry(t, c, resp, netip.Prefix{}, tc.staleFor, tc.leaseRemaining)
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

// A refresh and the removal race for the entry's claim, and only one wins.
// A claim taken between the pass selecting the entry and removing it keeps
// the entry for the refresh; a removal that wins holds the claim, so a
// refresh arriving after starts nothing.
func TestPruneAndRefreshShareTheClaim(t *testing.T) {
	for _, refreshFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "the refresh claims first", false: "the removal claims first"}[refreshFirst], func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024})
			defer c.Stop()
			req := new(dns.Msg)
			req.SetQuestion("claim.example.", dns.TypeA)
			e := seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Minute, 0)
			now := time.Now()
			var cur cache.PruneCursor
			for {
				_, done := c.store.positive.cache.Prune(&cur, func(v *CacheEntry) bool {
					selected := c.store.unservable(v, now)
					if selected && refreshFirst {
						v.prefetch.Store(true) // a refresh claims it between the scan and the removal
					}
					return selected
				}, func(v *CacheEntry) bool { return c.store.takeForPrune(v, now) })
				if done {
					break
				}
			}
			present := c.store.PositiveLen() == 1
			if refreshFirst != present {
				t.Fatalf("entry present %v after the pass, want %v", present, refreshFirst)
			}
			if !refreshFirst && e.prefetch.CompareAndSwap(false, true) {
				t.Fatal("a refresh could claim an entry the removal took")
			}
		})
	}
}
