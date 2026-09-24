package cache

import (
	"context"
	"math"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// storedAt is the instant the entry was admitted at.
func (e *CacheEntry) storedAt() time.Time { return monoEpoch.Add(time.Duration(e.stored)) }

// setStoredAt moves an entry's admission instant to t, the way tests age an
// entry without waiting.
func (e *CacheEntry) setStoredAt(t time.Time) { e.stored = monoOffset(t) }

// wallShifted returns t with its wall reading moved by d and its monotonic
// reading left alone: what an instant taken before a wall clock step looks
// like, measured against the clock after it. The time package offers no way
// to build one, so its layout is used directly; the caller checks the result.
func wallShifted(t time.Time, d time.Duration) time.Time {
	type layout struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	// The wall word holds seconds above 30 bits of nanoseconds.
	const nsecShift = 30
	// Audited: test only, and every caller verifies the result.
	r := (*layout)(unsafe.Pointer(&t)) //nolint:gosec // see above

	shifted := int64(r.wall) + int64(d/time.Second)<<nsecShift //nolint:gosec // bit layout
	r.wall = uint64(shifted)                                   //nolint:gosec // bit layout
	return t
}

// stepEpoch puts the entry epoch's wall reading a minute behind its
// monotonic one, as after a minute's wall clock step forward since startup,
// for the rest of the test.
func stepEpoch(t *testing.T) {
	t.Helper()
	saved := monoEpoch
	t.Cleanup(func() { monoEpoch = saved })
	now := time.Now()
	stepped := wallShifted(now, -time.Minute)
	if now.Round(0).Sub(stepped.Round(0)) != time.Minute || stepped.Sub(now) != 0 {
		t.Fatal("time.Time layout changed; update wallShifted")
	}
	monoEpoch = stepped
}

// clockAfter is now advanced by mono on the monotonic clock and by wall on
// the wall clock.
func clockAfter(t *testing.T, now time.Time, mono, wall time.Duration) time.Time {
	t.Helper()
	later := wallShifted(now.Add(mono), wall-mono)
	if later.Sub(now) != mono || later.Round(0).Sub(now.Round(0)) != wall {
		t.Fatal("time.Time layout changed; update wallShifted")
	}
	return later
}

// wallOnly drops t's monotonic reading, the form a signature expiry built
// with time.Unix arrives in.
func wallOnly(t time.Time) time.Time { return time.Unix(0, t.UnixNano()) }

// A lease that is a wall clock instant keeps the distance it names when the
// wall clock has stepped since startup, and ends when the wall clock reaches
// it after admission, even when the monotonic clock has not got that far. A
// lease with a monotonic reading keeps ignoring the wall clock.
func TestLeaseKeepsItsClock(t *testing.T) {
	stepEpoch(t)
	admit := time.Now()

	byWall := &CacheEntry{cutUntil: wallOnly(admit.Add(10 * time.Second))}
	byMono := &CacheEntry{cutUntil: admit.Add(10 * time.Second)}
	for _, e := range []*CacheEntry{byWall, byMono} {
		if _, lease := e.remainingBounds(admit); lease > 10*time.Second || lease < 9*time.Second {
			t.Fatalf("a ten second lease reads %v after a wall clock step before admission", lease)
		}
	}

	later := clockAfter(t, admit, time.Second, 61*time.Second)
	if _, lease := byWall.remainingBounds(later); lease > -50*time.Second {
		t.Fatalf("a wall clock lease reads %v after the wall clock passed it by 51s", lease)
	}
	if _, lease := byMono.remainingBounds(later); lease < 8*time.Second || lease > 9*time.Second {
		t.Fatalf("a monotonic lease reads %v, want the nine seconds the monotonic clock allows", lease)
	}
}

// An answer derived from a cached one inherits its lease as the lease is: a
// wall clock instant stays one, so the derived answer ends with its source
// when the wall clock reaches it, not seconds later.
func TestDerivedAnswerInheritsAWallClockLease(t *testing.T) {
	stepEpoch(t)
	admit := time.Now()

	source := NewCacheEntry(snapAnswer("a.test.", 300, "192.0.2.1"), 300*time.Second, 0)
	source.cutUntil = wallOnly(admit.Add(10 * time.Second))
	source.cutKey = 7

	var meta middleware.ResponseMeta
	boundRequestToEntryLifetime(middleware.WithResponseMeta(context.Background(), &meta), source)
	cut, key := meta.Cut()
	if cut.IsZero() || key != 7 {
		t.Fatalf("the derived answer's bound = (%v, %d), want the source's lease", cut, key)
	}
	derived := NewCacheEntry(snapAnswer("b.test.", 300, "192.0.2.2"), 300*time.Second, 0)
	derived.cutUntil, derived.cutKey = cut, key

	later := clockAfter(t, admit, time.Second, 61*time.Second)
	for name, e := range map[string]*CacheEntry{"source": source, "derived": derived} {
		if _, lease := e.remainingBounds(later); lease > -50*time.Second {
			t.Errorf("%s lease reads %v after the wall clock passed it by 51s", name, lease)
		}
		if ttl := e.servedTTL(later); ttl != 0 {
			t.Errorf("%s would still be served with TTL %d", name, ttl)
		}
	}
}

// A stale answer's TTL is what is left of its lease at the moment it is
// served, by the clock the lease is kept in.
func TestStaleTTLTakesTheWallClockLease(t *testing.T) {
	stepEpoch(t)
	admit := time.Now()

	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	req := new(dns.Msg)
	req.SetQuestion("a.test.", dns.TypeA)
	entry := NewCacheEntry(snapAnswer("a.test.", 300, "192.0.2.1"), time.Minute, 0)
	entry.setStoredAt(admit.Add(-2 * time.Minute))
	entry.cutUntil = wallOnly(admit.Add(10 * time.Second))

	now := clockAfter(t, admit, time.Second, 7*time.Second) // three seconds of lease left
	if _, lease := entry.remainingBounds(now); lease > 3*time.Second || lease < 2*time.Second {
		t.Fatalf("lease reads %v, want three seconds", lease)
	}
	got := c.staleResponseFromEntry(entry, req, false, now)
	if got.msg == nil {
		t.Fatal("no stale answer with three seconds of lease left")
	}
	for _, rr := range got.msg.Answer {
		if rr.Header().Ttl > 3 {
			t.Fatalf("stale answer published TTL %d with three seconds of lease left", rr.Header().Ttl)
		}
	}
}

// Converting instants centuries away keeps their sign rather than wrapping
// around to the other side of the epoch.
func TestMonoOffsetDoesNotWrap(t *testing.T) {
	if got := monoOffset(time.Unix(1<<40, 0)); got < math.MaxInt64/2 {
		t.Fatalf("far future converted to %d, want far in the future", got)
	}
	if got := monoOffset(time.Time{}); got > math.MinInt64/2 {
		t.Fatalf("zero time converted to %d, want far in the past", got)
	}
}

// A configured rate limit past the int32 range limits nothing, as before;
// it must not wrap to a small limit that throttles every hit.
func TestRateLimitNarrowsWithoutWrapping(t *testing.T) {
	// The values past int32 are int64 variables, converted only where int
	// holds them: as constants they would not compile on 32-bit platforms,
	// where int is int32 and no configuration can reach them anyway.
	fits := func(v int64) bool { return strconv.IntSize == 64 || (v >= math.MinInt32 && v <= math.MaxInt32) }
	for _, tc := range []struct {
		configured int64
		want       int32
	}{
		{0, 0},
		{-5, 0},
		{-4294967295, 0}, // wraps to 1 as a plain int32
		{100, 100},
		{math.MaxInt32, math.MaxInt32},
		{4294967297, math.MaxInt32}, // wraps to 1 as a plain int32
	} {
		if !fits(tc.configured) {
			continue
		}
		if got := clampRateLimit(int(tc.configured)); got != tc.want {
			t.Errorf("clampRateLimit(%d) = %d, want %d", tc.configured, got, tc.want)
		}
	}

	if strconv.IntSize < 64 {
		return
	}
	over, under := int64(4294967297), int64(-4294967295)
	e := NewCacheEntry(snapAnswer("a.test.", 300, "192.0.2.1"), time.Minute, int(over))
	if l := e.GetRateLimiter(); l == nil || l.Limit() < math.MaxInt32 {
		t.Fatalf("a rate limit past int32 became %v", l)
	}
	if NewCacheEntry(snapAnswer("a.test.", 300, "192.0.2.1"), time.Minute, int(under)).GetRateLimiter() != nil {
		t.Fatal("a negative rate limit became a limit")
	}
}
