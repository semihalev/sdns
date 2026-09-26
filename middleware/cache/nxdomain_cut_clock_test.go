package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// clockCut is a cache holding one validated cut for nxCutDeniedName,
// recorded under inherited. A non-zero stepped then replaces the cut's
// lease: the state a clock step leaves behind, one deadline passed on its
// own clock while the other still has time left.
func clockCut(t *testing.T, inherited, stepped lease.Lease) (*Cache, *nxDomainCutEntry) {
	t.Helper()
	c := New(&config.Config{CacheSize: 1024, Expire: 300})
	t.Cleanup(c.Stop)
	resp := nxCutValidatedResponse(nxCutRequest(nxCutDeniedName, dns.TypeA), nxCutDeniedName, nxCutZone)
	if !c.store.recordNXDomainCut(resp, nxCutDeniedName, nxCutZone, inherited) {
		t.Fatal("valid cut was not recorded")
	}
	cuts := c.store.nxDomainCuts
	cuts.mu.Lock()
	defer cuts.mu.Unlock()
	entry := cuts.entries[nxDomainCutID{deniedName: nxCutDeniedName, qclass: dns.ClassINET}]
	if entry == nil {
		t.Fatal("recorded cut not indexed")
	}
	if !stepped.IsZero() {
		entry.expires = stepped
	}
	return c, entry
}

// cutServePaths are the three ways a cut answers a descendant: the Msg
// path, the byte path, and the store's resolver-facing lookup. Each reports
// whether the cut served, and the lease the request tree was bound to.
var cutServePaths = []struct {
	name  string
	serve func(t *testing.T, c *Cache) (bool, lease.Lease)
}{
	{"msg", func(t *testing.T, c *Cache) (bool, lease.Lease) {
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)
		reached := false
		downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			reached = true
			resp := new(dns.Msg)
			resp.SetRcode(ch.Request.Msg(), dns.RcodeServerFailure)
			_ = ch.Writer.WriteMsg(resp)
			ch.Cancel()
		})
		w := mock.NewWriter("udp", "192.0.2.9:53000")
		ch := middleware.NewChain([]middleware.Handler{c, downstream})
		ch.Reset(w, nxCutRequest("child."+nxCutDeniedName, dns.TypeA))
		ch.Next(ctx)
		return !reached && w.Msg().Rcode == dns.RcodeNameError, meta.Cut()
	}},
	{"wire", func(t *testing.T, c *Cache) (bool, lease.Lease) {
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)
		req, _ := wireTestRequest(t, "child."+nxCutDeniedName, dns.TypeA, true)
		w := &sinkWriter{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
		ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
			ch.Cancel()
		})})
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		before := wireCutServed.Value()
		ch.Next(ctx)
		return wireCutServed.Value() != before, meta.Cut()
	}},
	{"store", func(_ *testing.T, c *Cache) (bool, lease.Lease) {
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)
		resp, ok := c.store.GetWithContext(ctx, nxCutRequest("child."+nxCutDeniedName, dns.TypeA))
		return ok && resp.Rcode == dns.RcodeNameError, meta.Cut()
	}},
}

// A cut keeps a wall-clock deadline beside its monotonic one: the proof's
// signature expiration as the calendar instant it is, or an inherited
// wall-clock lease when that ends first.
func TestNXDomainCutKeepsItsSignatureExpirationOnTheWallClock(t *testing.T) {
	now := time.Now()
	inheritedWall := wallOnly(now.Add(30 * time.Second))

	for _, tc := range []struct {
		name      string
		inherited lease.Lease
		// inheritedFirst: the inherited wall-clock lease ends before the
		// proof's signatures do, so it is the deadline.
		inheritedFirst bool
	}{
		{"no lease", lease.Lease{}, false},
		{"monotonic lease", lease.Of(now.Add(time.Minute), 1), false},
		{"wall-clock lease ending first", lease.Of(inheritedWall, 2), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cut := clockCut(t, tc.inherited, lease.Lease{})

			// The expected expiration is read off the proof the cut
			// admitted, the very records its deadline was computed from.
			var want time.Time
			for _, rr := range cut.msg.Ns {
				if sig, ok := rr.(*dns.RRSIG); ok {
					if at := time.Unix(int64(sig.Expiration), 0); want.IsZero() || at.Before(want) {
						want = at
					}
				}
			}
			if want.IsZero() {
				t.Fatal("bad fixture: the admitted proof holds no signature")
			}
			if tc.inheritedFirst {
				if !inheritedWall.Before(want) {
					t.Fatalf("bad fixture: the inherited lease %v does not end before the signatures %v", inheritedWall, want)
				}
				want = inheritedWall
			}

			wall := cut.expires.Wall().Until
			if !wall.Equal(want) || lease.Monotonic(wall) {
				t.Fatalf("wall-clock deadline %v (monotonic %v), want the calendar instant %v",
					wall, lease.Monotonic(wall), want)
			}
			if left := cut.expires.Mono().Until.Sub(cut.stored); left <= 0 || left > 300*time.Second {
				t.Fatalf("monotonic lifetime %v, want the proof TTL cap kept", left)
			}
		})
	}
}

// Every path a cut serves by hands the request tree the cut's deadline on
// both clocks, so an answer derived from it ends with the cut however the
// wall clock moves afterwards.
func TestNXDomainCutHitCarriesBothClocks(t *testing.T) {
	for _, path := range cutServePaths {
		t.Run(path.name, func(t *testing.T) {
			now := time.Now()
			inherited := lease.Of(now.Add(time.Minute), 1).Min(lease.Of(wallOnly(now.Add(30*time.Second)), 2))
			c, cut := clockCut(t, inherited, lease.Lease{})

			served, bound := path.serve(t, c)
			if !served {
				t.Fatal("the cut did not serve its descendant")
			}
			if !bound.Mono().Until.Equal(cut.expires.Mono().Until) ||
				!bound.Wall().Until.Equal(cut.expires.Wall().Until) {
				t.Fatalf("request tree bound to %+v, want the cut's %+v", bound, cut.expires)
			}

			admit := time.Now()
			derived := newCacheEntryAt(snapAnswer("derived.test.", 3600, "192.0.2.2"), time.Hour, 0, 0, admit)
			derived.setLease(bound)
			if derived.remaining(clockAfter(t, admit, time.Second, time.Second)) <= 0 {
				t.Fatal("bad fixture: the derived answer is dead with both clocks steady")
			}
			if left := derived.remaining(clockAfter(t, admit, time.Second, 31*time.Second)); left > 0 {
				t.Fatalf("wall clock jumped past the cut: the derived answer has %v left", left)
			}
			if left := derived.remaining(clockAfter(t, admit, 61*time.Second, 0)); left > 0 {
				t.Fatalf("wall clock held back past the cut's monotonic deadline: the derived answer has %v left", left)
			}
		})
	}
}

// A cut whose deadline has passed on either clock serves on no path, while
// the other clock still has time left.
func TestNXDomainCutNotServedPastEitherClock(t *testing.T) {
	now := time.Now()
	for _, step := range []struct {
		name string
		l    lease.Lease
	}{
		{"wall clock stepped past the wall-clock deadline",
			lease.Of(now.Add(time.Minute), 0).Min(lease.Of(wallOnly(now.Add(-time.Second)), 0))},
		{"monotonic deadline passed, wall clock stepped back",
			lease.Of(now.Add(-time.Second), 0).Min(lease.Of(wallOnly(now.Add(time.Hour)), 0))},
	} {
		for _, path := range cutServePaths {
			t.Run(step.name+"/"+path.name, func(t *testing.T) {
				c, _ := clockCut(t, lease.Lease{}, step.l)
				if served, _ := path.serve(t, c); served {
					t.Fatal("an expired cut served")
				}
			})
		}
	}
}

// leaseSink is a mock transport that leases bodies from its own buffer and
// discards what it is given, so a serve loop measures the serve alone.
type leaseSink struct {
	*mock.Writer
	buf [4096]byte
}

func (s *leaseSink) LeaseWire(capacity int) []byte {
	if capacity > len(s.buf) {
		return nil
	}
	return s.buf[:0]
}

func (s *leaseSink) Write(b []byte) (int, error) { return len(b), nil }

// A byte-path cut hit under a lease on both clocks, the hyperlocal root's
// shape, allocates nothing, the request tree's lease included.
func TestNXDomainCutWireHitWithBothClocksAllocatesNothing(t *testing.T) {
	now := time.Now()
	c, _ := clockCut(t, lease.Of(now.Add(time.Hour), 1).Min(lease.Of(wallOnly(now.Add(time.Hour)), 2)), lease.Lease{})
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	req, _ := wireTestRequest(t, "child."+nxCutDeniedName, dns.TypeA, true)
	w := &leaseSink{Writer: mock.NewWriter("udp", "192.0.2.9:53000")}
	ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		ch.Cancel()
	})})
	before := wireCutServed.Value()
	allocs := testing.AllocsPerRun(200, func() {
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
		ch.Next(ctx)
	})
	if wireCutServed.Value() == before {
		t.Fatal("the cut never served bytes; the pin measured nothing")
	}
	if meta.Cut().Wall().Until.IsZero() {
		t.Fatal("the hit did not bound the request tree on the wall clock")
	}
	if allocs != 0 {
		t.Fatalf("a wire cut hit allocated %.2f objects per serve; the contract is none", allocs)
	}
}
