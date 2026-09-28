package cache

import (
	"math/rand/v2"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pruneValue struct{ dead bool }

// A full pass removes exactly the values reported dead, keeps the rest,
// keeps the count honest, and reports its end once.
func TestPruneRemovesOnlyTheDead(t *testing.T) {
	c := New[*pruneValue](10000)
	live, dead := &pruneValue{}, &pruneValue{dead: true}
	for k := uint64(1); k <= 5000; k++ {
		if k%3 == 0 {
			c.Add(k, dead)
		} else {
			c.Add(k, live)
		}
	}
	var (
		cur     PruneCursor
		removed int
		passes  int
	)
	for passes == 0 {
		isDead := func(v *pruneValue) bool { return v.dead }
		n, done := c.Prune(&cur, isDead, isDead)
		removed += n
		if done {
			passes++
		}
	}
	if removed != 5000/3 {
		t.Fatalf("removed %d, want %d", removed, 5000/3)
	}
	if c.Len() != 5000-5000/3 {
		t.Fatalf("Len %d after the pass, want %d", c.Len(), 5000-5000/3)
	}
	for k := uint64(1); k <= 5000; k++ {
		v, ok := c.Get(k)
		if ok == (k%3 == 0) || (ok && v.dead) {
			t.Fatalf("key %d: present %v after the pass", k, ok)
		}
	}
}

// take has the last word, under the write lock: a value dead selected but
// take refuses stays.
func TestPruneTakeDecides(t *testing.T) {
	c := New[*pruneValue](1024)
	v := &pruneValue{dead: true}
	c.Add(9, v)
	var cur PruneCursor
	for {
		_, done := c.Prune(&cur, func(*pruneValue) bool { return true }, func(*pruneValue) bool { return false })
		if done {
			break
		}
	}
	if got, ok := c.Get(9); !ok || got != v {
		t.Fatal("a value take refused was removed")
	}
}

// A value replaced after the step read it is not the one it removes.
func TestPruneLeavesAReplacement(t *testing.T) {
	c := New[*pruneValue](1024)
	old, newer := &pruneValue{dead: true}, &pruneValue{dead: true}
	c.Add(7, old)
	var cur PruneCursor
	for {
		// dead is asked under the read lock. The replacement is queued for
		// the write lock by then, so it lands as the read lock goes, ahead
		// of the step's own write lock.
		_, done := c.Prune(&cur, func(v *pruneValue) bool {
			if v == old {
				go c.CompareAndSwap(7, old, newer)
				time.Sleep(10 * time.Millisecond)
				return true
			}
			return false
		}, func(*pruneValue) bool { return true })
		if done {
			break
		}
	}
	if v, ok := c.Get(7); !ok || v != newer {
		t.Fatalf("key 7 = %v (present %v), want the replacement kept", v, ok)
	}
}

// The latency of Get, the hit path, with the pruner stepping without rest,
// the worst it can do, against a cache with no pruner. Readers and a
// writer share the cache, as in production, so a sweep that held a
// segment lock long enough to stall the writer would stall the readers
// queued behind it; the tail shows it.
func TestGetLatencyWhilePruning(t *testing.T) {
	if os.Getenv("SDNS_PRUNE_PROBE") == "" {
		t.Skip("set SDNS_PRUNE_PROBE=1 to measure")
	}
	for round := range 3 {
		for _, mode := range []struct {
			name    string
			pruning bool
			rest    time.Duration
		}{
			{"no pruner", false, 0},
			{"paced as in production", true, 250 * time.Microsecond},
			{"without rest", true, 0},
		} {
			p99, p999, worst := getLatency(t, mode.pruning, mode.rest)
			t.Logf("round %d, %s: p99 %v, p99.9 %v, max %v", round, mode.name, p99, p999, worst)
		}
	}
}

func getLatency(t *testing.T, pruning bool, rest time.Duration) (p99, p999, worst time.Duration) {
	t.Helper()
	const n = 1 << 20
	c := New[*pruneValue](n)
	live, dead := &pruneValue{}, &pruneValue{dead: true}
	for k := uint64(1); k <= n; k++ {
		v := live
		if k%4 == 0 {
			v = dead
		}
		c.Add(k, v)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	if pruning {
		wg.Go(func() {
			var cur PruneCursor
			for !stop.Load() {
				isDead := func(v *pruneValue) bool { return v.dead }
				c.Prune(&cur, isDead, isDead)
				if rest > 0 {
					time.Sleep(rest)
				}
			}
		})
	}
	wg.Go(func() { // a writer keeping the dead share replenished
		r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404, a load generator
		for !stop.Load() {
			c.Add(r.Uint64N(n)+1, dead)
		}
	})

	const readers, samples = 4, 200000
	lat := make([][]time.Duration, readers)
	var rwg sync.WaitGroup
	for i := range readers {
		rwg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(i), 3)) //nolint:gosec // G404, a load generator
			out := make([]time.Duration, samples)
			for j := range samples {
				k := r.Uint64N(n) + 1
				start := time.Now()
				c.Get(k)
				out[j] = time.Since(start)
			}
			lat[i] = out
		})
	}
	rwg.Wait()
	stop.Store(true)
	wg.Wait()

	var all []time.Duration
	for _, l := range lat {
		all = append(all, l...)
	}
	slices.Sort(all)
	return all[len(all)*99/100], all[len(all)*999/1000], all[len(all)-1]
}
