package cache

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/lease"
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
			now := time.Now()
			if got := c.store.unservable(e, now); got != tc.want {
				t.Fatalf("unservable = %v, want %v", got, tc.want)
			}
			if !tc.refreshing {
				checkServableUntil(t, c.store, e, now)
			}
		})
	}
}

// checkServableUntil pins servableUntil to unservable: an answer's expiry
// record is filed for the instant unservable starts to hold, so up to it
// the answer is servable and from just past it on it is not. Filed early,
// the record would only come round again; filed late, the pruner would be
// late.
func checkServableUntil(t *testing.T, s *Store, e *CacheEntry, now time.Time) {
	t.Helper()
	const eps = time.Millisecond
	until := s.servableUntil(e, now)
	if until.IsZero() {
		if s.unservable(e, now.Add(100*365*24*time.Hour)) {
			t.Fatal("servableUntil has no end, but the answer becomes unservable")
		}
		return
	}
	if until.Sub(now) > eps && s.unservable(e, until.Add(-eps)) {
		t.Fatalf("unservable before servableUntil (%v from now)", until.Sub(now))
	}
	// An end already past is judged from now: unservable already holds.
	if !s.unservable(e, maxTime(until, now).Add(eps)) {
		t.Fatalf("still servable past servableUntil (%v from now)", until.Sub(now))
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// expiryClock moves the pruner's time by hand, the expiry index's and the
// one it judges answers by together: advance shifts both ahead of real
// time. It is set before anything is stored.
func expiryClock(c *Cache) (advance func(time.Duration)) {
	var shift atomic.Int64
	now := func() time.Time { return time.Now().Add(time.Duration(shift.Load())) }
	c.store.positive.cache.SetExpiryClock(now)
	c.store.pruneClock = now
	return func(d time.Duration) { shift.Add(int64(d)) }
}

// The pruner removes the expired answers once their records come due, and
// keeps the fresh ones.
func TestPruneRemovesTheUnservable(t *testing.T) {
	c := New(&config.Config{CacheSize: 4096})
	defer c.Stop()
	advance := expiryClock(c)
	for i, name := range []string{"a.example.", "b.example.", "c.example.", "d.example."} {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		staleFor := time.Minute
		if i%2 == 0 {
			staleFor = -time.Minute
		}
		seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, staleFor, 0)
	}
	if removed := c.store.prune(); removed != 0 {
		t.Fatalf("removed %d before any bucket passed", removed)
	}
	advance(15 * time.Second) // one bucket, about 14 s
	if removed := c.store.prune(); removed != 2 {
		t.Fatalf("removed %d, want the 2 expired", removed)
	}
	if n := c.store.PositiveLen(); n != 2 {
		t.Fatalf("%d answers left, want the 2 fresh", n)
	}
	// A minute later the fresh ones have run out too.
	advance(2 * time.Minute)
	if removed := c.store.prune(); removed != 2 || c.store.PositiveLen() != 0 {
		t.Fatalf("removed %d once the rest expired, want 2", removed)
	}
}

// A refresh and the removal race for the entry's claim, and only one wins.
// An entry a refresh has claimed stays for the refresh and is looked at
// again later; a removal that wins holds the claim, so a refresh arriving
// after starts nothing.
func TestPruneAndRefreshShareTheClaim(t *testing.T) {
	for _, refreshFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "the refresh claims first", false: "the removal claims first"}[refreshFirst], func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024})
			defer c.Stop()
			advance := expiryClock(c)
			req := new(dns.Msg)
			req.SetQuestion("claim.example.", dns.TypeA)
			e := seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Minute, 0)
			e.prefetch.Store(refreshFirst)
			advance(15 * time.Second)
			c.store.prune()
			present := c.store.PositiveLen() == 1
			if refreshFirst != present {
				t.Fatalf("entry present %v after the pass, want %v", present, refreshFirst)
			}
			if !refreshFirst {
				if e.prefetch.CompareAndSwap(false, true) {
					t.Fatal("a refresh could claim an entry the removal took")
				}
				return
			}
			// The refresh gives up its claim. A busy entry is filed a bucket
			// on, which lands it up to two buckets away, so two later it
			// is gone.
			e.prefetch.Store(false)
			advance(30 * time.Second)
			if removed := c.store.prune(); removed != 1 {
				t.Fatalf("a released entry: %d removed, want 1", removed)
			}
		})
	}
}

// An answer serve-stale may still answer from stays until
// serve_stale_max_ttl past its TTL, then goes.
func TestPruneWaitsOutServeStale(t *testing.T) {
	cfg := &config.Config{CacheSize: 1024, ServeStale: true}
	cfg.ServeStaleMaxTTL.Duration = time.Hour
	c := New(cfg)
	defer c.Stop()
	advance := expiryClock(c)
	req := new(dns.Msg)
	req.SetQuestion("stale.example.", dns.TypeA)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Minute, 0)

	advance(15 * time.Second)
	if removed := c.store.prune(); removed != 0 {
		t.Fatal("removed an answer serve-stale may still answer from")
	}
	// Its stale window ends 59 minutes from now, inside the next hour.
	advance(time.Hour)
	if removed := c.store.prune(); removed != 1 {
		t.Fatalf("past its stale window: %d removed, want 1", removed)
	}
}

// A refresh that replaces an answer leaves the new one to its own record:
// the old record finds it servable and does not remove it.
func TestPruneLeavesARefreshedAnswer(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()
	advance := expiryClock(c)
	req := new(dns.Msg)
	req.SetQuestion("refreshed.example.", dns.TypeA)
	old := seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, -10*time.Second, 0)
	key := CacheKey{Question: req.Question[0]}.Hash()
	if !c.store.ReplaceIfCurrent(key, old, staleTestAnswer(req, "192.0.2.2"), lease.Lease{}) {
		t.Fatal("the refresh did not replace the answer")
	}
	advance(30 * time.Second) // past the old answer's end, not the new one's
	if removed := c.store.prune(); removed != 0 {
		t.Fatal("the old record removed the refreshed answer")
	}
	if c.store.PositiveLen() != 1 {
		t.Fatal("the refreshed answer is gone")
	}
}

// An answer whose record comes due while it is still servable, as it is
// when a wall-clock lease was read before the clock stepped back, keeps
// its tracking: the pruner files it again at the end it has now and
// removes it once that has passed, instead of dropping its only record.
func TestPruneKeepsTrackingAnAnswerFoundServable(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()
	start := time.Now()
	var index, judge atomic.Int64 // offsets from start
	c.store.positive.cache.SetExpiryClock(func() time.Time { return start.Add(time.Duration(index.Load())) })
	c.store.pruneClock = func() time.Time { return start.Add(time.Duration(judge.Load())) }

	req := new(dns.Msg)
	req.SetQuestion("rollback.example.", dns.TypeA)
	// Fresh for 20 s more: its record is filed for then.
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, -20*time.Second, 0)

	// The index passes that end, but the verdict's clock reads 10 s: still
	// servable.
	index.Store(int64(40 * time.Second))
	judge.Store(int64(10 * time.Second))
	if removed := c.store.prune(); removed != 0 {
		t.Fatal("removed an answer the verdict found servable")
	}
	// Both clocks move past its end: the refiled record removes it.
	index.Store(int64(80 * time.Second))
	judge.Store(int64(80 * time.Second))
	if removed := c.store.prune(); removed != 1 || c.store.PositiveLen() != 0 {
		t.Fatalf("pruned %d, %d left; the answer lost its tracking", removed, c.store.PositiveLen())
	}
}
