package cache

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// expiring is a value that knows when it is dead, on the test's clock.
type expiring struct {
	mark ExpiryMark
	dies int64 // nanoseconds on the test clock since the index epoch
	busy bool
}

func markOfExpiring(v *expiring) *ExpiryMark { return &v.mark }

// testExpiry builds a cache with a 256 s ring (one-second buckets) and a
// clock the test moves. judge calls a value dead from its own end on.
func testExpiry(t *testing.T, size int) (*Cache[*expiring], *atomic.Int64, func(*expiring) (Verdict, time.Time)) {
	t.Helper()
	c := NewWithExpiry(size, 256*time.Second, markOfExpiring)
	var clock atomic.Int64 // nanoseconds since the index's epoch
	c.SetExpiryClock(func() time.Time { return c.exp.epoch.Add(time.Duration(clock.Load())) })
	judge := func(v *expiring) (Verdict, time.Time) {
		switch {
		case v.busy:
			return Busy, time.Time{}
		case v.dies <= clock.Load():
			return Dead, time.Time{}
		}
		return Alive, c.exp.epoch.Add(time.Duration(v.dies))
	}
	return c, &clock, judge
}

// put stores v under key, dying life from the clock's now, and files it
// for that end.
func put(c *Cache[*expiring], clock *atomic.Int64, key uint64, v *expiring, life time.Duration) {
	v.dies = clock.Load() + int64(life)
	c.AddUntil(key, v, c.exp.epoch.Add(time.Duration(v.dies)))
}

// filed counts the records the index holds, stale ones included.
func filed(c *Cache[*expiring]) (n int) {
	for s := range c.exp.shards {
		for _, b := range c.exp.shards[s].ring {
			n += len(b)
		}
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
	if n := c.exp.records.Load(); n != 0 {
		t.Fatalf("%d records counted with nothing filed", n)
	}
}

// A key whose value was replaced by a longer-lived one keeps the new
// value when the old record fires, which is stale and dropped, and loses
// it when its own does.
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
	if n := filed(c); n != 1 {
		t.Fatalf("%d records after the stale one fired, want the new value's 1", n)
	}
	clock.Store(int64(102 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("the new value's own record removed %d, want 1", removed)
	}
}

// A record that fires before its value is dead, whatever made it early,
// a wall clock stepped back or a tick judged late, is filed again for the
// end the owner reports now, and the value is removed at that end.
func TestExpireRefilesARecordThatFiresEarly(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	v := &expiring{}
	put(c, clock, 8, v, 10*time.Second)
	v.dies = int64(40 * time.Second) // it turns out to live longer

	clock.Store(int64(12 * time.Second))
	if removed := c.Expire(judge); removed != 0 {
		t.Fatal("removed a value still alive")
	}
	if n := filed(c); n != 1 {
		t.Fatalf("%d records after the early fire, want it filed again", n)
	}
	clock.Store(int64(42 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("at its real end: %d removed, want 1", removed)
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

// An end beyond the ring waits in its last bucket, comes round, and is
// still found.
func TestExpireFindsAnEndBeyondTheRing(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	put(c, clock, 11, &expiring{}, 1000*time.Second)

	for s := int64(10); s < 1000; s += 10 {
		clock.Store(s * int64(time.Second))
		if removed := c.Expire(judge); removed != 0 {
			t.Fatalf("removed at %d s, before it died", s)
		}
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
	put(c, clock, 9, &expiring{}, time.Second)
	clock.Store(int64(102 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("a record filed behind the ring: %d removed, want 1", removed)
	}
}

// The zero time files nothing: that value is never expired, and a value
// found alive with no end any more is retired from the index.
func TestExpireIgnoresAValueWithNoEnd(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	c.AddUntil(5, &expiring{dies: 0}, time.Time{})
	clock.Store(int64(10000 * time.Second))
	if removed := c.Expire(judge); removed != 0 || filed(c) != 0 {
		t.Fatal("an untracked value was expired or filed")
	}

	put(c, clock, 6, &expiring{}, time.Second)
	endless := func(*expiring) (Verdict, time.Time) { return Alive, time.Time{} }
	clock.Add(int64(3 * time.Second))
	c.Expire(endless)
	if n := filed(c); n != 0 {
		t.Fatalf("%d records left for a value with no end, want 0", n)
	}
}

// A lifetime already over on arrival, a deadline that passed on the way
// to the insert, is due at once.
func TestExpireTakesAPastEndAsDue(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	clock.Store(int64(10 * time.Second))
	put(c, clock, 5, &expiring{}, -time.Second)
	clock.Store(int64(12 * time.Second))
	if removed := c.Expire(judge); removed != 1 {
		t.Fatalf("a value dead on arrival: %d removed, want 1", removed)
	}
}

// A judge that calls a value alive with an end already past is asked once
// per Expire, however far behind the pass is: the value comes round in a
// later pass, not in every bucket this one still has to fire.
func TestExpireEndsOnAnAliveVerdictInThePast(t *testing.T) {
	c, clock, _ := testExpiry(t, 1024)
	put(c, clock, 12, &expiring{}, time.Second)
	var asked int
	stubborn := func(*expiring) (Verdict, time.Time) { asked++; return Alive, c.exp.epoch }
	clock.Store(int64(100 * time.Second))
	done := make(chan struct{})
	go func() { c.Expire(stubborn); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Expire did not return")
	}
	if asked != 1 {
		t.Fatalf("the judge was asked %d times in one pass, want 1", asked)
	}
	if n := filed(c); n != 1 {
		t.Fatalf("%d records, want the value filed once for a later pass", n)
	}
}

// Inserts that fail file nothing, and a cache without the index expires
// nothing.
func TestExpireFilesOnlyWhatWasStored(t *testing.T) {
	c, clock, judge := testExpiry(t, 1024)
	put(c, clock, 1, &expiring{}, 100*time.Second)
	soon := c.exp.epoch.Add(time.Second)
	if c.AddIfAbsentUntil(1, &expiring{}, soon) {
		t.Fatal("AddIfAbsentUntil stored over a present key")
	}
	if c.CompareAndSwapUntil(1, &expiring{}, &expiring{}, soon) {
		t.Fatal("CompareAndSwapUntil swapped a different value")
	}
	if n := filed(c); n != 1 {
		t.Fatalf("%d records filed, want 1", n)
	}
	clock.Store(int64(50 * time.Second))
	if c.Expire(judge) != 0 {
		t.Fatal("a failed insert's record removed the stored value")
	}

	plain := New[*expiring](16)
	plain.AddUntil(1, &expiring{}, time.Now().Add(time.Second))
	if plain.Expire(judge) != 0 || plain.Len() != 1 {
		t.Fatal("a cache without an index expired something")
	}
}

// The index is bounded by the cache's occupancy, not by how often keys
// are written: one key refreshed every 100 s with a 1000 s life, and a
// cache of 64 churning a thousand writes a second, both with Expire
// running, hold a handful of records, not one per write.
func TestExpireBoundsTheIndexUnderChurn(t *testing.T) {
	defer func(s int64) { compactSlack = s }(compactSlack)
	compactSlack = 128

	t.Run("one key refreshed", func(t *testing.T) {
		c, clock, judge := testExpiry(t, 1024)
		for s := int64(0); s < 20000; s += 10 {
			clock.Store(s * int64(time.Second))
			if s%100 == 0 {
				put(c, clock, 1, &expiring{}, 1000*time.Second)
			}
			c.Expire(judge)
		}
		if n := filed(c); n > 4 {
			t.Fatalf("%d records for one live value", n)
		}
		t.Logf("after 200 refreshes over 5h33m: %d records for one live value", filed(c))
	})
	t.Run("eviction churn", func(t *testing.T) {
		c, clock, judge := testExpiry(t, 64)
		key := uint64(0)
		for s := int64(0); s < 600; s++ {
			clock.Store(s * int64(time.Second))
			for range 1000 {
				key++
				put(c, clock, key, &expiring{}, 200*time.Second)
			}
			c.Expire(judge)
		}
		if n, bound := int64(filed(c)), 2*int64(c.Len())+compactSlack+1000; n > bound {
			t.Fatalf("%d records for %d values, over %d", n, c.Len(), bound)
		}
		var capacity int
		for s := range c.exp.shards {
			for _, b := range c.exp.shards[s].ring {
				capacity += cap(b)
			}
		}
		t.Logf("after 600,000 writes over 10 min: %d records, %d B of slices, for %d values",
			filed(c), capacity*8, c.Len())
		if n := c.exp.records.Load(); n != int64(filed(c)) {
			t.Fatalf("records counted %d, filed %d", n, filed(c))
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

// The owner's bit and the mark share one word without disturbing each
// other.
func TestExpiryMarkKeepsTheOwnersBit(t *testing.T) {
	var m ExpiryMark
	m.SetFlag(true)
	m.setMark(markOf(12345))
	if !m.Flag() || m.mark() != markOf(12345) {
		t.Fatal("setting the mark lost the flag")
	}
	if !m.CompareAndSwapFlag(true, false) || m.Flag() || m.mark() != markOf(12345) {
		t.Fatal("clearing the flag lost the mark")
	}
	if m.CompareAndSwapFlag(true, false) {
		t.Fatal("swapped a flag that was not set")
	}
	m.SetFlag(true)
	m.setMark(0)
	if !m.Flag() || m.mark() != 0 {
		t.Fatal("unmarking lost the flag")
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
				c.AddUntil(key, v, c.exp.epoch.Add(time.Duration(v.dies)))
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
	b.Run("Add", func(b *testing.B) {
		c := New[*expiring](1 << 20)
		v := &expiring{}
		b.ReportAllocs()
		for i := uint64(0); b.Loop(); i++ {
			c.Add(i&(1<<20-1)+1, v)
		}
	})
	b.Run("AddUntil", func(b *testing.B) {
		c := NewWithExpiry(1<<20, 4*time.Hour, markOfExpiring)
		vs := make([]expiring, 1<<20)
		start := time.Now()
		b.ReportAllocs()
		for i := uint64(0); b.Loop(); i++ {
			k := i & (1<<20 - 1)
			c.AddUntil(k+1, &vs[k], start.Add(time.Duration(i%3600)*time.Second))
		}
		var bytes int
		for s := range c.exp.shards {
			for _, r := range c.exp.shards[s].ring {
				bytes += cap(r) * 8
			}
		}
		if n := filed(c); n > 0 {
			b.ReportMetric(float64(bytes)/float64(n), "index-B/record")
		}
	})
}
