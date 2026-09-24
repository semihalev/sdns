package cache

import (
	"math"
	"strconv"
	"testing"
	"time"
	"unsafe"
)

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

// A deadline carrying only a wall reading, a signature's expiry built with
// time.Unix, keeps the distance it names when the wall clock has stepped
// since startup. Measured against the epoch's wall reading instead, a minute
// forward turned a ten second lease into seventy.
func TestWallOnlyDeadlineSurvivesAWallClockStep(t *testing.T) {
	saved := monoEpoch
	t.Cleanup(func() { monoEpoch = saved })

	// The epoch's wall reads a minute behind its monotonic one: the wall
	// clock has stepped a minute forward since the process started.
	now := time.Now()
	stepped := wallShifted(now, -time.Minute)
	if got := now.Round(0).Sub(stepped.Round(0)); got != time.Minute {
		t.Fatalf("time.Time layout changed: wall shift moved %v, want 1m; update wallShifted", got)
	}
	if stepped.Sub(now) != 0 {
		t.Fatal("time.Time layout changed: the monotonic reading moved; update wallShifted")
	}
	monoEpoch = stepped

	for _, tc := range []struct {
		name     string
		deadline time.Time
	}{
		{"wall reading only", time.Unix(0, time.Now().Add(10*time.Second).UnixNano())},
		{"with a monotonic reading", time.Now().Add(10 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &CacheEntry{}
			e.setCutUntil(tc.deadline)
			_, lease := e.remainingBounds(time.Now())
			if lease > 10*time.Second || lease < 9*time.Second {
				t.Fatalf("a ten second lease reads %v after a wall clock step", lease)
			}
		})
	}
}

// A lease given as a wall clock instant ends when the wall clock reaches
// it, also when the wall clock gets there after admission faster than the
// monotonic clock does: a minute's step forward expires a ten second lease
// the monotonic clock alone would still honor for nine. A lease with a
// monotonic reading keeps ignoring the wall clock.
func TestWallOnlyDeadlineFollowsTheWallClockAfterAdmission(t *testing.T) {
	admit := time.Now()
	later := wallShifted(admit.Add(time.Second), time.Minute) // monotonic +1s, wall +61s
	if later.Sub(admit) != time.Second || later.Round(0).Sub(admit.Round(0)) != 61*time.Second {
		t.Fatal("time.Time layout changed; update wallShifted")
	}

	wallOnly := &CacheEntry{}
	wallOnly.setCutUntil(time.Unix(0, admit.Add(10*time.Second).UnixNano()))
	if _, lease := wallOnly.remainingBounds(later); lease > -50*time.Second {
		t.Fatalf("a wall clock lease reads %v left after the wall clock passed it by 51s", lease)
	}

	monotonic := &CacheEntry{}
	monotonic.setCutUntil(admit.Add(10 * time.Second))
	if _, lease := monotonic.remainingBounds(later); lease < 8*time.Second || lease > 9*time.Second {
		t.Fatalf("a monotonic lease reads %v, want the nine seconds the monotonic clock allows", lease)
	}

	// Dropping the lease drops the wall clock end with it, and the rare
	// part when nothing else needs it.
	wallOnly.setCutUntil(time.Time{})
	if wallOnly.hasCut() || wallOnly.rare != nil {
		t.Fatal("clearing the lease left part of it behind")
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
