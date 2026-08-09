package cache

import (
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests pin down the eviction contract for a cache that sits on the
// resolver's hot path. They encode two properties the 2026-07-28 incident
// proved we need (1.43M goroutines, 93% blocked behind cache segment locks
// while eviction storms dumped glue entries mid-outage):
//
//  1. Proportionality — evicting is allowed to remove roughly as much as the
//     overshoot, not a double-digit percentage of the whole cache. During an
//     upstream outage every dumped glue entry converts directly into a fresh
//     recursive resolution, so bulk eviction feeds the very load that caused
//     it.
//  2. Bounded latency — one Add must never stall behind bulk work done on
//     behalf of other keys. The cache is the heart of SDNS; capacity
//     pressure is its normal operating state on a busy node, not an edge
//     case.

// TestEvictionProportionalityAtCapacity holds the cache at capacity and
// feeds it one insert at a time — the steady state of a busy resolver.
// Each insert may evict on the order of its own overshoot (plus a small
// batch buffer), and the population must never crater.
func TestEvictionProportionalityAtCapacity(t *testing.T) {
	const maxSize = 200_000

	c := New(maxSize)
	for i := 0; i < maxSize; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}
	if got := c.Len(); got != maxSize {
		t.Fatalf("fill: Len = %d, want %d", got, maxSize)
	}

	// Worst single-step drop and lowest population observed while inserting
	// fresh keys against a full cache.
	minLen := maxSize
	worstDrop := 0
	const inserts = 1_000
	for i := 0; i < inserts; i++ {
		before := c.Len()
		c.Add(uint64(maxSize+i), i) //nolint:gosec // G115 - test loop
		after := c.Len()

		if drop := before - after; drop > worstDrop {
			worstDrop = drop
		}
		if after < minLen {
			minLen = after
		}
	}

	t.Logf("inserts=%d worst_single_add_drop=%d min_len=%d (max=%d)",
		inserts, worstDrop, minLen, maxSize)

	// One insert carries one entry of overshoot. Allow a generous batch
	// buffer (1% of capacity) so an amortized small-batch evictor still
	// passes; segment nuking (10-60% per event) must not.
	if limit := maxSize / 100; worstDrop > limit {
		t.Errorf("single Add evicted %d entries, want <= %d (1%% of capacity); "+
			"eviction work must be proportional to overshoot, not cache size",
			worstDrop, limit)
	}
	if floor := maxSize * 95 / 100; minLen < floor {
		t.Errorf("population fell to %d during steady-state inserts, want >= %d (95%% of capacity); "+
			"every dumped entry is a cache miss the resolver pays for again",
			minLen, floor)
	}
}

// TestAddLatencyUnderEvictionStorm keeps the cache at capacity while
// concurrent writers insert fresh keys and readers keep probing — the
// incident-night workload. It asserts a hard per-operation latency bound:
// whatever bookkeeping eviction does, no single Add or Get may stall behind
// bulk work.
func TestAddLatencyUnderEvictionStorm(t *testing.T) {
	if testing.Short() {
		t.Skip("storm test skipped in -short")
	}

	const (
		maxSize  = 1 << 20 // 1M — production glue/message cache scale
		writers  = 16
		readers  = 8
		duration = 2 * time.Second
		maxStall = 50 * time.Millisecond
	)

	c := New(maxSize)
	for i := 0; i < maxSize; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - test loop
	}

	var (
		stop     atomic.Bool
		nextKey  atomic.Uint64
		totalOps atomic.Int64
		mu       sync.Mutex
		addLat   []time.Duration
		getLat   []time.Duration
	)
	nextKey.Store(maxSize)

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 1<<14)
			for !stop.Load() {
				k := nextKey.Add(1)
				start := time.Now()
				c.Add(k, int(k)) //nolint:gosec // G115 - test key
				local = append(local, time.Since(start))
				totalOps.Add(1)
			}
			mu.Lock()
			addLat = append(addLat, local...)
			mu.Unlock()
		}()
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			local := make([]time.Duration, 0, 1<<14)
			for i := seed; !stop.Load(); i += 7 {
				start := time.Now()
				c.Get(i % maxSize)
				local = append(local, time.Since(start))
				totalOps.Add(1)
			}
			mu.Lock()
			getLat = append(getLat, local...)
			mu.Unlock()
		}(uint64(r) * 131)
	}

	time.Sleep(duration)
	stop.Store(true)
	wg.Wait()

	stats := func(name string, lat []time.Duration) (p99, max time.Duration) {
		if len(lat) == 0 {
			t.Fatalf("%s: no samples", name)
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		p99 = lat[len(lat)*99/100]
		max = lat[len(lat)-1]
		t.Logf("%s: samples=%d p99=%v max=%v", name, len(lat), p99, max)
		return p99, max
	}

	t.Logf("total_ops=%d len_after=%d (max=%d)", totalOps.Load(), c.Len(), maxSize)
	addP99, addMax := stats("add", addLat)
	getP99, getMax := stats("get", getLat)

	// p99 is the portable regression signal: bulk-eviction stalls (the
	// 2026-07-28 mode — writers queued behind segment clearing) drag the
	// p99 across a fraction of hundreds of thousands of samples, while a
	// shared CI runner descheduling one goroutine for half a second moves
	// only the tail maximum. Assert the absolute-stall bound too, but only
	// on dedicated hardware where the max measures the cache and not the
	// neighbour's build.
	if addP99 > maxStall {
		t.Errorf("Add p99 %v under eviction storm, want < %v; "+
			"inserts are queueing behind bulk eviction work",
			addP99, maxStall)
	}
	if getP99 > maxStall {
		t.Errorf("Get p99 %v under eviction storm, want < %v; "+
			"reads are queueing behind bulk eviction work",
			getP99, maxStall)
	}
	if !isCI() {
		if addMax > maxStall {
			t.Errorf("Add stalled %v under eviction storm, want < %v; "+
				"an insert must never wait on bulk eviction work",
				addMax, maxStall)
		}
		if getMax > maxStall {
			t.Errorf("Get stalled %v under eviction storm, want < %v; "+
				"reads must never wait on bulk eviction work",
				getMax, maxStall)
		}
	}
}

// BenchmarkAddAtCapacity documents the steady-state insert cost against a
// full cache — the number that regresses if eviction grows work per Add.
// Compare with BenchmarkAddUnderCapacity for the eviction overhead itself.
func BenchmarkAddAtCapacity(b *testing.B) {
	const maxSize = 1 << 18

	c := New(maxSize)
	for i := 0; i < maxSize; i++ {
		c.Add(uint64(i), i) //nolint:gosec // G115 - bench setup
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var k uint64
		for pb.Next() {
			k++
			c.Add(uint64(maxSize)+k<<20, int(k)) //nolint:gosec // G115 - bench key
		}
	})
}

// BenchmarkAddUnderCapacity is the no-eviction baseline for the pair.
func BenchmarkAddUnderCapacity(b *testing.B) {
	const maxSize = 1 << 30 // never reached

	c := New(1 << 18)
	c.maxSize = maxSize

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var k uint64
		for pb.Next() {
			k++
			c.Add(k, int(k)) //nolint:gosec // G115 - bench key
		}
	})
}
