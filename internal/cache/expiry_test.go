package cache

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// expiring is a value that knows when it is dead, on the test's clock.
type expiring struct {
	dies int64 // nanoseconds on the test clock
	busy bool
}

// testExpiry builds a cache with a 256 s ring (one-second buckets) and a
// clock the test moves.
func testExpiry(t *testing.T, size int) (*Cache[*expiring], *atomic.Int64, func(*expiring) (Verdict, time.Duration)) {
	t.Helper()
	c := NewWithExpiry[*expiring](size, 256*time.Second)
	var clock atomic.Int64
	c.exp.now = clock.Load
	judge := func(v *expiring) (Verdict, time.Duration) {
		left := time.Duration(v.dies - clock.Load())
		switch {
		case v.busy:
			return Busy, 0
		case left <= 0:
			return Dead, 0
		}
		return Alive, left
	}
	return c, &clock, judge
}

// put stores v under key, dying life from the clock's now.
func put(c *Cache[*expiring], clock *atomic.Int64, key uint64, v *expiring, life time.Duration) {
	v.dies = clock.Load() + int64(life)
	c.AddFor(key, v, life)
}

// filed counts the records the index holds.
func filed(c *Cache[*expiring]) (n int) {
	for s := range c.exp.shards {
		sh := &c.exp.shards[s]
		for _, b := range sh.ring {
			n += len(b)
		}
		n += len(sh.far)
	}
	return n
}

// A value is found once its bucket has wholly passed, and not before.
func TestExpireRemovesWhatHasDied(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	for k := uint64(1); k <= 100; k++ {
		put(c, clock, k, &expiring{}, time.Duration(k)*time.Second)
	}
	clock.Store(int64(50 * time.Second))
	removed := c.Expire(judge)
	// Keys 1..49 lived until second 49 at the latest, inside buckets 1..49,
	// all passed. Key 50 dies at 50, in bucket 50, which has not.
	if removed != 49 {
		t.Fatalf("removed %d at 50 s, want 49", removed)
	}
	for k := uint64(1); k <= 100; k++ {
		if _, ok := c.Get(k); ok != (k >= 50) {
			t.Fatalf("key %d present = %v at 50 s", k, ok)
		}
	}
	clock.Store(int64(101 * time.Second))
	if removed := c.Expire(judge); removed != 51 || c.Len() != 0 {
		t.Fatalf("removed %d at 101 s, %d left; want 51 and 0", removed, c.Len())
	}
}

// A key whose value was replaced by a longer-lived one keeps the new
// value when the old record fires, and loses it when its own does.
func TestExpireLeavesAReplacedValueToItsOwnRecord(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	put(c, clock, 7, &expiring{}, 10*time.Second)
	put(c, clock, 7, &expiring{}, 100*time.Second)

	clock.Store(int64(20 * time.Second))
	if removed := c.Expire(judge); removed != 0 {
		t.Fatalf("the old record removed the new value (%d removed)", removed)
	}
	if _, ok := c.Get(7); !ok {
		t.Fatal("the new value is gone")
	}
	// The old record is dropped, not filed again: the new value's own
	// record is the only one left.
	if n := filed(c); n != 1 {
		t.Fatalf("%d records after the old one fired, want 1", n)
	}
	clock.Store(int64(102 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("the new value's own record removed %d, want 1", removed)
	}
}

// A value the owner cannot judge yet is looked at again a bucket later,
// and removed once it can be.
func TestExpireRetriesABusyValue(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	v := &expiring{busy: true}
	put(c, clock, 3, v, 5*time.Second)

	clock.Store(int64(10 * time.Second))
	if removed := c.Expire(judge); removed != 0 {
		t.Fatal("a busy value was removed")
	}
	v.busy = false
	clock.Store(int64(12 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("the retried busy value: %d removed, want 1", removed)
	}
}

// A lifetime beyond the ring waits in the far list and is still found.
func TestExpireFindsALifetimeBeyondTheRing(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	put(c, clock, 11, &expiring{}, 1000*time.Second)

	clock.Store(int64(999 * time.Second))
	if removed := c.Expire(judge); removed != 0 {
		t.Fatal("removed before it died")
	}
	clock.Store(int64(1002 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("a far value: %d removed, want 1", removed)
	}
}

// Expire that has not run for longer than the whole ring still finds
// everything that died meanwhile.
func TestExpireCatchesUpAfterAPause(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	for k := uint64(1); k <= 50; k++ {
		put(c, clock, k, &expiring{}, time.Duration(k*10)*time.Second)
	}
	clock.Store(int64(2000 * time.Second))
	// Values filed while Expire lags keep their own time.
	put(c, clock, 99, &expiring{}, 30*time.Second)
	if removed := c.Expire(judge); removed != 50 {
		t.Fatalf("after a pause: %d removed, want 50", removed)
	}
	clock.Store(int64(2031 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("a value filed during the pause: %d removed, want 1", removed)
	}
}

// A writer that read the clock before Expire fired its bucket files into
// the first bucket still to fire, not into the fired slot, which now
// stands for a bucket a whole ring later.
func TestExpireFilesAStaleReadIntoTheNextBucket(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	clock.Store(int64(100 * time.Second))
	c.Expire(judge) // buckets up to 99 have fired
	clock.Store(int64(50 * time.Second))
	c.AddFor(9, &expiring{dies: int64(51 * time.Second)}, time.Second)
	clock.Store(int64(102 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("a record filed behind the ring: %d removed, want 1", removed)
	}
}

// Forever files nothing: that value is never expired.
func TestExpireIgnoresAValueWithNoEnd(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	c.AddFor(5, &expiring{dies: 0}, Forever)
	clock.Store(int64(10000 * time.Second))
	if removed := c.Expire(judge); removed != 0 {
		t.Fatal("an untracked value was expired")
	}
}

// A lifetime already over on arrival, a deadline that passed on the way
// to the insert, is due at once, not taken for one with no end.
func TestExpireTakesANegativeLifetimeAsDue(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	clock.Store(int64(10 * time.Second))
	c.AddFor(5, &expiring{dies: int64(9 * time.Second)}, -time.Second)
	clock.Store(int64(12 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("a value dead on arrival: %d removed, want 1", removed)
	}
}

// Inserts that fail file nothing, and a cache without the index expires
// nothing.
func TestExpireFilesOnlyWhatWasStored(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	first := &expiring{}
	put(c, clock, 1, first, 100*time.Second)
	if c.AddIfAbsentFor(1, &expiring{}, time.Second) {
		t.Fatal("AddIfAbsentFor stored over a present key")
	}
	if c.CompareAndSwapFor(1, &expiring{}, &expiring{}, time.Second) {
		t.Fatal("CompareAndSwapFor swapped a different value")
	}
	if n := filed(c); n != 1 {
		t.Fatalf("%d records filed, want 1", n)
	}
	clock.Store(int64(50 * time.Second))
	if c.Expire(judge) != 0 {
		t.Fatal("a failed insert's record removed the stored value")
	}

	plain := New[*expiring](16)
	plain.AddFor(1, &expiring{}, time.Second)
	if plain.Expire(judge) != 0 || plain.Len() != 1 {
		t.Fatal("a cache without an index expired something")
	}
}

// Writers and Expire run together without a race and without losing a
// value that has died.
func TestExpireUnderConcurrentWriters(t *testing.T) {
	c, clock, judge := testExpiry(t, 1<<20)
	var wg sync.WaitGroup
	for w := range uint64(8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range uint64(2000) {
				key := w*10000 + i + 1
				v := &expiring{dies: clock.Load() + int64(time.Duration(i%60+1)*time.Second)}
				c.AddFor(key, v, time.Duration(v.dies-clock.Load()))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			clock.Add(int64(time.Second / 4))
			c.Expire(judge)
		}
	}()
	wg.Wait()
	clock.Add(int64(200 * time.Second))
	c.Expire(judge)
	if n := c.Len(); n != 0 {
		t.Fatalf("%d values outlived every lifetime", n)
	}
}

// BenchmarkExpiryInsert compares an insert without the index against one
// that files its key, and reports the index's bytes per record.
func BenchmarkExpiryInsert(b *testing.B) {
	v := &expiring{}
	b.Run("Add", func(b *testing.B) {
		c := New[*expiring](1 << 20)
		b.ReportAllocs()
		for i := uint64(0); b.Loop(); i++ {
			c.Add(i&(1<<20-1)+1, v)
		}
	})
	b.Run("AddFor", func(b *testing.B) {
		c := NewWithExpiry[*expiring](1<<20, 4*time.Hour)
		b.ReportAllocs()
		for i := uint64(0); b.Loop(); i++ {
			c.AddFor(i&(1<<20-1)+1, v, time.Duration(i%3600)*time.Second)
		}
		var bytes int
		for s := range c.exp.shards {
			for _, r := range c.exp.shards[s].ring {
				bytes += cap(r) * 8
			}
		}
		if n := filed(any(c).(*Cache[*expiring])); n > 0 {
			b.ReportMetric(float64(bytes)/float64(n), "index-B/record")
		}
	})
}

// Records of evicted values find nothing when they fire, and the count
// stays true: a cache far over its capacity evicts most of what it was
// given, and expiring the rest leaves it empty, not below zero.
func TestExpireAfterEviction(t *testing.T) {
	c, clock, judge := testExpiry(t, 64)
	for k := uint64(1); k <= 5000; k++ {
		put(c, clock, k, &expiring{}, time.Duration(k%30+1)*time.Second)
	}
	if n := c.Len(); n > 64 {
		t.Fatalf("%d stored, over the capacity of 64", n)
	}
	kept := c.Len()
	clock.Store(int64(40 * time.Second))
	if removed := c.Expire(judge); removed != kept {
		t.Fatalf("removed %d, want the %d eviction left", removed, kept)
	}
	if n := c.Len(); n != 0 {
		t.Fatalf("Len %d after everything expired", n)
	}
}
