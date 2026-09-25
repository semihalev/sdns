package cache

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/middleware"
)

// An answer derived from a cached one is admitted the way the store admits
// it: its own TTL from the served one, with the positive floor applied, and
// the lease the request tree accumulated.
func deriveAt(t *testing.T, source *CacheEntry, hit time.Time) *CacheEntry {
	t.Helper()
	var meta middleware.ResponseMeta
	boundRequestToEntryLifetime(middleware.WithResponseMeta(context.Background(), &meta), source)

	msg := snapAnswer("derived.test.", source.servedTTL(hit), "192.0.2.2")
	mt, _ := dnsutil.ClassifyResponse(msg, hit)
	ttl := NewTTLManager(minTTL, maxTTL).Bound(dnsutil.CalculateCacheTTLAt(msg, mt, hit))
	derived := newCacheEntryAt(msg, ttl, 0, 0, hit)
	derived.setLease(meta.Cut())
	return derived
}

// A monotonic TTL and a wall-clock lease cannot be ordered at the hit: which
// ends first depends on how the wall clock moves afterwards. Whatever it
// does, an answer derived from a cached one must not outlive it, so both
// bounds have to reach the derived answer.
func TestDerivedAnswerNeverOutlivesItsSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		// The source's own TTL runs on the monotonic clock; its lease is a
		// wall-clock instant this far after admission.
		ttl, wallLease time.Duration
		// Where the two clocks stand, from admission, at the hit and later.
		hitMono, hitWall, laterMono, laterWall time.Duration
	}{
		// The wall clock stepped ahead before the hit, then back: the lease
		// looked nearer at the hit, and the TTL ends first.
		{"wall step before the hit", 10 * time.Second, 20 * time.Second,
			8 * time.Second, 19 * time.Second, 11 * time.Second, 19 * time.Second},
		// No step before the hit; the wall clock goes back after it.
		{"wall rollback after the hit", 10 * time.Second, 9 * time.Second,
			8 * time.Second, 8 * time.Second, 11 * time.Second, 6 * time.Second},
		// The wall clock jumps ahead after the hit and reaches the lease
		// long before the TTL runs out.
		{"wall jump after the hit", 10 * time.Second, 9 * time.Second,
			2 * time.Second, 2 * time.Second, 3 * time.Second, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admit := time.Now()
			source := newCacheEntryAt(snapAnswer("source.test.", uint32(tc.ttl/time.Second), "192.0.2.1"), tc.ttl, 0, 0, admit) //nolint:gosec // seconds
			source.setLease(lease.Of(wallOnly(admit.Add(tc.wallLease)), 7))

			derived := deriveAt(t, source, clockAfter(t, admit, tc.hitMono, tc.hitWall))

			later := clockAfter(t, admit, tc.laterMono, tc.laterWall)
			if source.remaining(later) > 0 {
				t.Fatalf("bad fixture: the source is still live at %v", source.remaining(later))
			}
			if got := derived.remaining(later); got > 0 {
				t.Fatalf("the derived answer outlives its source by %v", got)
			}
		})
	}
}

// The store keeps a lease on both clocks whole, whichever way the entry is
// admitted, and a scoped entry keeps its scope beside it.
func TestStoreKeepsBothClocksOfALease(t *testing.T) {
	now := time.Now()
	cut := lease.Of(now.Add(time.Minute), 1).Min(lease.Of(wallOnly(now.Add(2*time.Minute)), 2))
	same := func(t *testing.T, e *CacheEntry) {
		t.Helper()
		got := e.lease()
		if got.Mono() != cut.Mono() || !got.Wall().Until.Equal(cut.Wall().Until) || got.Wall().Key != 2 {
			t.Fatalf("entry lease = %+v, want %+v", got, cut)
		}
	}

	s := NewStore(
		NewPositiveCache(1024, minTTL, maxTTL, &CacheMetrics{}),
		NewNegativeCache(1024, minTTL, time.Hour, &CacheMetrics{}),
		CacheConfig{},
	)
	resp := snapAnswer("both.test.", 300, "192.0.2.1")
	key := CacheKey{Question: resp.Question[0]}.Hash()

	s.SetFromResponseWithCut(resp, false, cut)
	entry, ok := s.LookupByKey(key)
	if !ok {
		t.Fatal("answer not cached")
	}
	same(t, entry)

	if !s.ReplaceIfCurrent(key, entry, snapAnswer("both.test.", 600, "192.0.2.3"), cut) {
		t.Fatal("refresh not stored")
	}
	refreshed, _ := s.LookupByKey(key)
	same(t, refreshed)

	scope := netip.MustParsePrefix("192.0.2.0/24")
	scopedKey := CacheKey{Question: resp.Question[0], Scope: scope}.Hash()
	s.SetFromResponseScoped(scopedKey, resp, scope, cut)
	scoped, ok := s.LookupByKey(scopedKey)
	if !ok {
		t.Fatal("scoped answer not cached")
	}
	same(t, scoped)
	if scoped.scopeKey() != scope {
		t.Fatalf("scope = %v, want %v beside the lease", scoped.scopeKey(), scope)
	}

	// A monotonic lease alone costs a plain entry nothing extra.
	s.SetFromResponseWithCut(resp, false, lease.Of(now.Add(time.Minute), 1))
	plain, _ := s.LookupByKey(key)
	if plain.rare != nil {
		t.Fatal("a monotonic lease allocated the rare part")
	}
}

// A snapshot keeps a lease as a duration a restore counts on the monotonic
// clock, so an answer bound by a wall-clock deadline is not saved.
func TestSnapshotLeavesOutWallClockLeases(t *testing.T) {
	dir := t.TempDir()
	cfg := persistConfig(t, dir)
	now := time.Now()

	before := New(cfg)
	before.SetTrustAnchors(anchorsOf(anchorA))
	before.store.SetFromResponseWithCut(snapAnswer("mono.test.", 300, "192.0.2.1"), false,
		lease.Of(now.Add(time.Hour), 1))
	before.store.SetFromResponseWithCut(snapAnswer("wall.test.", 300, "192.0.2.2"), false,
		lease.Of(now.Add(time.Hour), 1).Min(lease.Of(wallOnly(now.Add(time.Hour)), 2)))
	before.Persist(context.Background())

	after := New(cfg)
	after.SetTrustAnchors(anchorsOf(anchorA))
	after.Restore()
	if storedEntry(after.store, "mono.test.", false) == nil {
		t.Fatal("an answer under a monotonic lease was not restored")
	}
	if storedEntry(after.store, "wall.test.", false) != nil {
		t.Fatal("an answer under a wall-clock lease came back as a monotonic one")
	}
}

// Serve-stale bounds what is derived from a stale answer by both clocks of
// its lease, beside the stale window.
func TestStaleBoundKeepsBothClocks(t *testing.T) {
	now := time.Now()
	entry := NewCacheEntry(snapAnswer("stale.test.", 300, "192.0.2.1"), 300*time.Second, 0)
	wall := wallOnly(now.Add(10 * time.Second))
	entry.setLease(lease.Of(now.Add(time.Hour), 1).Min(lease.Of(wall, 2)))

	var meta middleware.ResponseMeta
	boundRequestToStaleLifetime(middleware.WithResponseMeta(context.Background(), &meta), entry, now)
	cut := meta.Cut()
	if !cut.Wall().Until.Equal(wall) || cut.Wall().Key != 2 {
		t.Fatalf("stale bound = %+v, lost the wall-clock lease", cut)
	}
	if !cut.Mono().Until.Equal(now.Add(staleAnswerTTL)) {
		t.Fatalf("stale bound = %+v, want the stale window on the monotonic clock", cut)
	}
}
