package lease

import (
	"testing"
	"time"
)

func wallOnly(t time.Time) time.Time { return time.Unix(0, t.UnixNano()) }

func TestOfSortsByClock(t *testing.T) {
	now := time.Now()
	if l := Of(now.Add(time.Second), 1); l.Mono().Until.IsZero() || !l.Wall().Until.IsZero() {
		t.Fatalf("a deadline from time.Now was not kept as monotonic: %+v", l)
	}
	if l := Of(wallOnly(now), 1); !l.Mono().Until.IsZero() || l.Wall().Until.IsZero() {
		t.Fatalf("a calendar deadline was not kept as wall clock: %+v", l)
	}
	if !Of(time.Time{}, 1).IsZero() {
		t.Fatal("a zero deadline is unbounded")
	}
}

// The two kinds never displace each other, whichever looks earlier.
func TestMinKeepsBothKinds(t *testing.T) {
	now := time.Now()
	l := Of(now.Add(10*time.Second), 1).Min(Of(wallOnly(now.Add(5*time.Second)), 2))
	if l.Mono().Key != 1 || l.Wall().Key != 2 {
		t.Fatalf("a deadline of one kind displaced the other: %+v", l)
	}
	l = l.Min(Of(now.Add(3*time.Second), 3)).Min(Of(wallOnly(now.Add(time.Hour)), 4))
	if l.Mono().Key != 3 || l.Wall().Key != 2 {
		t.Fatalf("Min did not keep the earlier deadline of each kind: %+v", l)
	}
}

func TestMinKeepsTheReceiverOnATie(t *testing.T) {
	at := time.Now().Add(time.Minute)
	if l := Of(at, 1).Min(Of(at, 2)); l.Mono().Key != 1 {
		t.Fatalf("an exactly inherited deadline was relabelled: key %d", l.Mono().Key)
	}
}

func TestRemainingReadsEachClock(t *testing.T) {
	now := time.Now()
	l := Of(now.Add(10*time.Second), 0).Min(Of(wallOnly(now.Add(20*time.Second)), 0))
	if d, ok := l.Remaining(now); !ok || d < 9*time.Second || d > 10*time.Second {
		t.Fatalf("Remaining = %v, %v, want the monotonic ten seconds", d, ok)
	}
	if _, ok := (Lease{}).Remaining(now); ok {
		t.Fatal("an unbounded lease reported a bound")
	}
	if (Lease{}).Expired(now.Add(time.Hour)) {
		t.Fatal("an unbounded lease expired")
	}
	if !l.Expired(now.Add(10 * time.Second)) {
		t.Fatal("a lease did not expire at its deadline")
	}
}

func TestKeyedRelabelsOnlyWhatIsHeld(t *testing.T) {
	l := Of(time.Now().Add(time.Second), 1).Keyed(9)
	if l.Mono().Key != 9 || l.Wall() != (Bound{}) {
		t.Fatalf("Keyed = %+v", l)
	}
}
