package metric

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// promValue reads the current value of a Prometheus counter via the
// model interface. Avoids depending on client_golang's testutil
// package, which pulls in heavier deps.
func promValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("counter Write: %v", err)
	}
	if m.Counter == nil || m.Counter.Value == nil {
		return 0
	}
	return *m.Counter.Value
}

// newTestCounter builds a Counter without touching the global
// Prometheus registry — tests can run repeatedly without
// duplicate-registration panics.
func newTestCounter(name string) (*Counter, prometheus.Counter) {
	prom := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "test"})
	c := &Counter{prom: prom}
	return c, prom
}

// newTestCounterVec builds a CounterVec without touching the global
// Prometheus registry. Mirrors NewCounterVec but uses a fresh
// CounterVec each call so re-running the test never panics on
// duplicate registration.
func newTestCounterVec(name string, labels []string) *CounterVec {
	pv := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: "test"}, labels)
	cv := &CounterVec{promVec: pv, arity: len(labels)}
	empty := map[string]*Counter{}
	cv.m.Store(&empty)
	return cv
}

func TestCounterIncBasic(t *testing.T) {
	c, _ := newTestCounter("test_inc_basic")

	for range 100 {
		c.Inc()
	}

	if got := c.Value(); got != 100 {
		t.Errorf("Value = %d, want 100", got)
	}
}

func TestCounterAdd(t *testing.T) {
	c, _ := newTestCounter("test_add")

	c.Add(5)
	c.Add(7)
	c.Add(13)

	if got := c.Value(); got != 25 {
		t.Errorf("Value = %d, want 25", got)
	}
}

func TestCounterFlushPushesDelta(t *testing.T) {
	c, prom := newTestCounter("test_flush_delta")

	c.Add(10)
	c.flush()
	if got := promValue(t, prom); got != 10 {
		t.Errorf("after first flush, prom = %v, want 10", got)
	}

	c.Add(5)
	c.flush()
	if got := promValue(t, prom); got != 15 {
		t.Errorf("after second flush, prom = %v, want 15 (10 + 5 delta)", got)
	}
}

func TestCounterFlushIsIdempotent(t *testing.T) {
	c, prom := newTestCounter("test_flush_idempotent")

	c.Add(42)
	c.flush()
	c.flush()
	c.flush()

	if got := promValue(t, prom); got != 42 {
		t.Errorf("after 3 flushes with no new writes, prom = %v, want 42", got)
	}
}

func TestCounterFlushWithNoData(t *testing.T) {
	c, prom := newTestCounter("test_flush_empty")

	c.flush()
	if got := promValue(t, prom); got != 0 {
		t.Errorf("flush of empty counter = %v, want 0", got)
	}
}

// TestCounterConcurrentInc proves the hot path doesn't lose writes
// under contention. Run with -race; the per-shard atomic add is
// fully synchronised by sync/atomic semantics.
func TestCounterConcurrentInc(t *testing.T) {
	c, prom := newTestCounter("test_concurrent_inc")

	const goroutines = 64
	const perGoroutine = 10_000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				c.Inc()
			}
		}()
	}
	wg.Wait()

	want := int64(goroutines * perGoroutine)
	if got := c.Value(); got != want {
		t.Errorf("Value after concurrent Inc = %d, want %d (lost %d)", got, want, want-got)
	}

	c.flush()
	if got := promValue(t, prom); got != float64(want) {
		t.Errorf("Prom value after flush = %v, want %d", got, want)
	}
}

// TestCounterConcurrentIncAndFlush runs Inc and flush concurrently to
// catch races between hot-path writers and the background flusher.
// flush only reads atomic shard values + touches lastSent (single-
// writer field), so no atomic on lastSent should be required.
func TestCounterConcurrentIncAndFlush(t *testing.T) {
	c, prom := newTestCounter("test_concurrent_inc_flush")

	const writers = 16
	const writes = 5_000
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			for range writes {
				c.Inc()
			}
		}()
	}

	// Flusher races alongside writers.
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		for {
			select {
			case <-stop:
				return
			default:
				c.flush()
				time.Sleep(time.Microsecond)
			}
		}
	}()

	wg.Wait()
	close(stop)
	<-flushDone

	c.flush() // catch any tail writes
	want := int64(writers * writes)
	if got := c.Value(); got != want {
		t.Errorf("Value = %d, want %d", got, want)
	}
	if got := promValue(t, prom); got != float64(want) {
		t.Errorf("Prom value = %v, want %d", got, want)
	}
}

// TestCounterShardsAreUsed sanity-checks that procPin actually spreads
// writes. With many goroutines, more than one shard should have a non-
// zero value. This is informational — flaky if Go's scheduler happens
// to pin everything to one P during the test, but on multi-core
// runners that essentially never happens.
func TestCounterShardsAreUsed(t *testing.T) {
	c, _ := newTestCounter("test_shards_used")

	var wg sync.WaitGroup
	wg.Add(32)
	for range 32 {
		go func() {
			defer wg.Done()
			for range 1000 {
				c.Inc()
			}
		}()
	}
	wg.Wait()

	used := 0
	for i := range c.shards {
		if c.shards[i].v.Load() > 0 {
			used++
		}
	}
	if used < 2 {
		t.Logf("only %d shard(s) used — scheduler may have pinned everything to one P. Not a failure, but unusual.", used)
	}
}

func TestCounterVecLazyCreate(t *testing.T) {
	cv := newTestCounterVec("test_vec_lazy", []string{"outcome"})

	c1 := cv.WithLabelValues("hit")
	c2 := cv.WithLabelValues("miss")
	c3 := cv.WithLabelValues("hit") // should reuse c1

	if c1 == c2 {
		t.Errorf("distinct labels returned the same counter")
	}
	if c1 != c3 {
		t.Errorf("same label returned different counters across calls")
	}

	c1.Inc()
	c1.Inc()
	c2.Inc()

	if got := c1.Value(); got != 2 {
		t.Errorf("c1.Value = %d, want 2", got)
	}
	if got := c2.Value(); got != 1 {
		t.Errorf("c2.Value = %d, want 1", got)
	}
}

// TestCounterVecConcurrentCreate stresses the create() path with many
// goroutines racing to register the same brand-new tuple. Only one
// Counter should win, and all goroutines must observe the same
// pointer. Catches double-create bugs in the LoadOrStore equivalent
// (re-check under writeMu).
func TestCounterVecConcurrentCreate(t *testing.T) {
	cv := newTestCounterVec("test_vec_concurrent", []string{"outcome"})

	const goroutines = 64
	results := make([]*Counter, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			<-start
			results[i] = cv.WithLabelValues("brand_new")
		}()
	}
	close(start)
	wg.Wait()

	first := results[0]
	for i, c := range results {
		if c != first {
			t.Errorf("goroutine %d got different counter pointer", i)
		}
	}

	// All Inc calls below land on the single shared counter.
	for _, c := range results {
		c.Inc()
	}
	if got := first.Value(); got != int64(goroutines) {
		t.Errorf("Value = %d, want %d", got, goroutines)
	}
}

// TestCounterVecConcurrentCreateDistinct stresses the create() path
// with many goroutines registering DIFFERENT tuples — exercises the
// map-copy step under the writeMu. Map grows from 0 to N entries.
func TestCounterVecConcurrentCreateDistinct(t *testing.T) {
	cv := newTestCounterVec("test_vec_distinct", []string{"outcome"})

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("outcome_%d", i)
			c := cv.WithLabelValues(key)
			c.Inc()
		}()
	}
	wg.Wait()

	m := cv.m.Load()
	if len(*m) != goroutines {
		t.Errorf("map size = %d, want %d", len(*m), goroutines)
	}
	for i := range goroutines {
		key := fmt.Sprintf("outcome_%d", i)
		c, ok := (*m)[key]
		if !ok {
			t.Errorf("key %q missing from map", key)
			continue
		}
		if got := c.Value(); got != 1 {
			t.Errorf("counter for %q = %d, want 1", key, got)
		}
	}
}

func TestJoinLabels(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{"empty", nil},
		{"single", []string{"foo"}},
		{"two", []string{"A", "NOERROR"}},
		{"three", []string{"a", "b", "c"}},
		{"with empty", []string{"a", "", "c"}},
	}
	// We don't pin exact bytes — the encoding format is internal.
	// What we DO pin: each input produces a distinct encoding.
	seen := map[string]string{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(encodeKey(nil, tc.values))
			if prev, ok := seen[got]; ok && prev != tc.name {
				t.Errorf("encodeKey(%q) collided with %q encoding", tc.values, prev)
			}
			seen[got] = tc.name
		})
	}
}

// TestEncodeKeyCollisionResistance covers the bugs the old
// separator-based joinLabels would silently allow:
//
//   - ("a", "bc") vs ("ab", "c") — boundary ambiguity
//   - ("a\x1Fb",) vs ("a", "b") — separator-in-value collision
//   - () vs ("",) — zero-arity vs one-empty-value collision
//
// All three pairs must encode to distinct keys.
func TestEncodeKeyCollisionResistance(t *testing.T) {
	pairs := [][2][]string{
		{{"a", "bc"}, {"ab", "c"}},
		{{"a\x1fb"}, {"a", "b"}},
		{nil, {""}},
		{{""}, {"", ""}},
	}
	for i, p := range pairs {
		a := string(encodeKey(nil, p[0]))
		b := string(encodeKey(nil, p[1]))
		if a == b {
			t.Errorf("pair %d: %q and %q encode to the same key %q", i, p[0], p[1], a)
		}
	}
}

// TestFlusherLifecycle: the flusher starts on first counter
// registration, a tick publishes counts to Prometheus, and Stop()
// drains the final flush so no counts are lost at shutdown.
func TestFlusherLifecycle(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()

	SetFlushInterval(10 * time.Millisecond)
	c := NewCounter(prometheus.NewRegistry(),
		prometheus.CounterOpts{Name: "test_flusher_lifecycle", Help: "t"})

	for range 7 {
		c.Inc()
	}
	time.Sleep(40 * time.Millisecond)
	if got := promValue(t, c.prom); got != 7 {
		t.Errorf("after tick, prom = %v, want 7", got)
	}

	c.Add(3)
	Stop()

	if got := promValue(t, c.prom); got != 10 {
		t.Errorf("after Stop, prom = %v, want 10 (final-flush captured the 3)", got)
	}
}

// TestStopIdempotent: Stop must be safe to call multiple times.
func TestStopIdempotent(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()

	NewCounter(prometheus.NewRegistry(),
		prometheus.CounterOpts{Name: "test_stop_idempotent", Help: "t"})
	Stop()
	Stop() // must not panic
}

// TestStopBeforeAnyCounter: Stop with no counters ever registered
// must be a no-op (flusher never started).
func TestStopBeforeAnyCounter(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()
	Stop() // must not panic, must not block
}

// TestSetFlushIntervalValidates: zero / negative intervals must
// panic loudly rather than tripping time.NewTicker inside the
// goroutine.
func TestSetFlushIntervalValidates(t *testing.T) {
	t.Cleanup(resetForTest)

	t.Run("zero", func(t *testing.T) {
		resetForTest()
		defer func() {
			if r := recover(); r == nil {
				t.Error("SetFlushInterval(0) did not panic")
			}
		}()
		SetFlushInterval(0)
	})
	t.Run("negative", func(t *testing.T) {
		resetForTest()
		defer func() {
			if r := recover(); r == nil {
				t.Error("SetFlushInterval(-1) did not panic")
			}
		}()
		SetFlushInterval(-1 * time.Second)
	})
}

// TestSetFlushIntervalAfterStartPanics: changing the interval after
// the flusher is already running cannot work (ticker is fixed) and
// silently doing nothing would be worse than panic.
func TestSetFlushIntervalAfterStartPanics(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()

	NewCounter(prometheus.NewRegistry(),
		prometheus.CounterOpts{Name: "test_set_after_start", Help: "t"})

	defer func() {
		if r := recover(); r == nil {
			t.Error("SetFlushInterval after first counter did not panic")
		}
	}()
	SetFlushInterval(5 * time.Second)
}

// TestLazyAutoStart: registering a Counter must implicitly start
// the flusher — no caller-visible StartFlusher needed.
func TestLazyAutoStart(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()
	SetFlushInterval(10 * time.Millisecond)

	c := NewCounter(prometheus.NewRegistry(),
		prometheus.CounterOpts{Name: "test_lazy_start", Help: "t"})
	c.Add(5)

	time.Sleep(40 * time.Millisecond)
	if got := promValue(t, c.prom); got != 5 {
		t.Errorf("auto-started flusher didn't publish: prom = %v, want 5", got)
	}
}

// TestNoNewCounterLost: a Counter registered while flushAll is
// already iterating the snapshot must NOT cause a flush-skip on the
// next tick. The "add mid-flush" race is the dangerous one.
func TestNoNewCounterLost(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()

	cv := newTestCounterVec("test_no_lost", []string{"k"})

	// Pre-create some counters and seed values to give flushAll work.
	for i := range 10 {
		c := cv.WithLabelValues(fmt.Sprintf("k%d", i))
		c.Add(int64(i + 1))
	}

	// Fire flushAll and a new counter creation in parallel.
	var newCounter atomic.Pointer[Counter]
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		FlushAll()
	}()
	go func() {
		defer wg.Done()
		c := cv.WithLabelValues("brand_new_mid_flush")
		c.Add(99)
		newCounter.Store(c)
	}()
	wg.Wait()

	// Now run FlushAll again. The new counter MUST be in the snapshot
	// this time and its 99 should reach Prometheus.
	FlushAll()
	nc := newCounter.Load()
	if nc == nil {
		t.Fatal("test bug: newCounter not stored")
	}
	if got := promValue(t, nc.prom); got != 99 {
		t.Errorf("new counter's Prom value after second flushAll = %v, want 99", got)
	}
}

// TestCounterAddNegativeDeltaPanics: Prometheus counters disallow
// negative additions, and our flush logic would silently swallow
// later positive increments after a negative add. Add must panic
// instead.
func TestCounterAddNegativeDeltaPanics(t *testing.T) {
	c, _ := newTestCounter("test_add_negative")
	defer func() {
		if r := recover(); r == nil {
			t.Error("Counter.Add(-1) did not panic")
		}
	}()
	c.Add(-1)
}

// TestCounterVecArityMismatchPanics: calling WithLabelValues with
// the wrong number of values must panic, matching prometheus.
// CounterVec semantics. Without this guard, a bad-arity call could
// collide-hit a cached key and silently increment the wrong series.
func TestCounterVecArityMismatchPanics(t *testing.T) {
	cv := newTestCounterVec("test_vec_arity", []string{"qtype", "rcode"})

	t.Run("too few", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("WithLabelValues with too few values did not panic")
			}
		}()
		cv.WithLabelValues("A")
	})
	t.Run("too many", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("WithLabelValues with too many values did not panic")
			}
		}()
		cv.WithLabelValues("A", "NOERROR", "extra")
	})
}

// TestCounterVecMultiLabelCollisionFree: encode + lookup for multi-
// label vectors must distinguish boundary-ambiguous tuples that
// would have collided under the old separator-based encoding.
func TestCounterVecMultiLabelCollisionFree(t *testing.T) {
	cv := newTestCounterVec("test_vec_multilabel_collision", []string{"a", "b"})

	c1 := cv.WithLabelValues("a", "bc")
	c2 := cv.WithLabelValues("ab", "c")
	c3 := cv.WithLabelValues("a\x1fb", "c")

	if c1 == c2 || c1 == c3 || c2 == c3 {
		t.Errorf("collision: c1=%p c2=%p c3=%p", c1, c2, c3)
	}

	c1.Add(10)
	c2.Add(20)
	c3.Add(30)

	if got := c1.Value(); got != 10 {
		t.Errorf("c1.Value = %d, want 10", got)
	}
	if got := c2.Value(); got != 20 {
		t.Errorf("c2.Value = %d, want 20", got)
	}
	if got := c3.Value(); got != 30 {
		t.Errorf("c3.Value = %d, want 30", got)
	}
}

// TestStopConcurrent: many goroutines call Stop() at the same time.
// sync.Once around the close + drain must keep this safe.
func TestStopConcurrent(t *testing.T) {
	t.Cleanup(resetForTest)
	resetForTest()

	NewCounter(prometheus.NewRegistry(),
		prometheus.CounterOpts{Name: "test_stop_concurrent", Help: "t"})

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		wg.Go(func() {
			<-start
			Stop()
		})
	}
	close(start)
	wg.Wait() // must not panic
}
