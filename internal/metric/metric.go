// Package metric is a thin shim over Prometheus that trades a small
// amount of staleness for a much faster hot path.
//
// # Why it exists
//
// A direct Prometheus counter is already one atomic add internally —
// fast in isolation, but a single shared cache line under heavy
// concurrent contention (~33 ns/op on an 8-core M5). The Vec form
// adds a per-call WithLabelValues map lookup that pushes the
// contended cost to ~120 ns/op. Multiplied across every middleware
// in a busy SDNS process, this is real CPU.
//
// metric's hot path:
//
//   - For an unlabeled Counter: runtime.procPin + an atomic add on a
//     per-CPU shard. ~2 ns/op under 8-core contention. There is no
//     shared cache line — each P writes its own.
//   - For a CounterVec: an atomic.Pointer load of an immutable label-
//     tuple map (rare write, COW) + map lookup, then the same
//     per-CPU shard add as above. ~7 ns/op under 8-core contention
//     for single-label vectors, ~12 ns/op for multi-label vectors
//     (a pooled buffer + unsafe.String view keeps the hit path
//     allocation-free even with multi-byte length-prefixed keys).
//
// # Lifecycle
//
// The flush goroutine starts automatically on first NewCounter or
// NewCounterVec call and ticks at the configured interval (default
// 1 s; override with SetFlushInterval BEFORE the first counter is
// created). Each tick sums every Counter's shards and pushes the
// delta into the underlying Prometheus counter via Add. Prometheus'
// scraped value therefore lags by at most one flush interval —
// invisible at the typical 15-s scrape, since rate() operates over
// windows that dwarf the flush interval.
//
// At shutdown, callers MUST invoke Stop() to drain the final flush
// before the process exits — otherwise up to one flush interval of
// counts is lost. Stop is safe to call multiple times and from
// multiple goroutines concurrently.
//
// # Constructors and registries
//
// NewCounter and NewCounterVec take a prometheus.Registerer. Pass
// nil to use prometheus.DefaultRegisterer. Tests should pass a
// fresh prometheus.NewRegistry() so repeated construction never
// hits the MustRegister duplicate-collector panic.
//
// # Cost model
//
// Memory: each Counter is shardCount * 64 B = 512 B (8 cache-line-
// padded atomics). A CounterVec with N distinct label tuples
// allocates N Counters + one immutable map of N entries.
//
// Crash safety: up to one flush interval of un-flushed counts is
// lost on process death. Acceptable for ops metrics.
//
// Concurrency: Counter.Inc/Add and CounterVec.WithLabelValues are
// safe for unlimited concurrent calls. The flusher runs in one
// dedicated goroutine and reads each Counter's lastSent without
// synchronization — that field is owned by the flusher; the
// registry's flushMu serialises all flush passes.
//
// # Limitations
//
// CounterVec is intended for CLOSED label sets — qtypes, rcodes,
// named outcomes, etc. — where the cardinality is bounded by code
// rather than by traffic. There is no Delete or unregister API:
// every distinct label tuple stays in the COW map and the flush
// registry for the rest of the process lifetime. Metrics with
// runtime-unbounded labels (per-domain, per-client-IP) should use
// prometheus.CounterVec directly and manage their own LRU eviction
// (see middleware/metrics for the existing pattern).
//
// Histograms are intentionally out of scope. Bucket counts don't
// compose under delta-flush the way scalars do, and the histogram
// hot-path cost (~260 ns under 8-core contention) is dominated by
// bucket lookup, not by cache-line contention. Sampling at the
// observation site is the right answer for hot-path histograms.
package metric

import (
	"encoding/binary"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
)

//go:linkname runtime_procPin runtime.procPin
func runtime_procPin() int

//go:linkname runtime_procUnpin runtime.procUnpin
func runtime_procUnpin()

// shardCount is the number of per-CPU shards each Counter holds.
// Must be a power of two so the pid -> shard mapping is one AND.
// 8 covers typical edge-box CPU counts (4-8 cores) without false
// sharing; servers with >8 cores spread writes across the same 8
// lines, which still wins on contention but does not scale linearly.
// Bumping to 32 buys headroom at 4x memory; leave it 8 until profiles
// say otherwise.
const shardCount = 8

// paddedAtomic places one atomic.Int64 on its own 64-byte cache line
// so two adjacent shards never share an L1 line.
type paddedAtomic struct {
	v atomic.Int64
	_ [56]byte
}

// Counter is a sharded counter that mirrors into a Prometheus Counter
// on a background tick. Inc and Add are the hot path; flush is called
// by the registry.
//
// The lastSent field is touched only by the flusher goroutine. The
// registry serialises flushes per counter via its own snapshot, so no
// atomic is needed here.
type Counter struct {
	shards   [shardCount]paddedAtomic
	prom     prometheus.Counter
	lastSent int64
}

// NewCounter constructs a Counter, registers the underlying
// prometheus.Counter with reg (or prometheus.DefaultRegisterer when
// reg is nil), enrolls it in metric's flush loop, and starts the
// background flusher on first call. Panics on duplicate registration
// (matches prometheus.MustRegister semantics so misconfiguration
// fails loudly at boot).
//
// Tests should pass a fresh prometheus.NewRegistry() so repeated
// construction across test runs never collides.
func NewCounter(reg prometheus.Registerer, opts prometheus.CounterOpts) *Counter {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	prom := prometheus.NewCounter(opts)
	reg.MustRegister(prom)
	c := &Counter{prom: prom}
	defaultRegistry.add(c)
	ensureFlusher()
	return c
}

// Inc adds one to the counter.
func (c *Counter) Inc() { c.Add(1) }

// Add adds delta to the counter. Panics on negative delta, matching
// prometheus.Counter.Add semantics — a negative add would also
// silently deduct from a future positive add by lowering sum below
// lastSent, so refusing it at the call site is the loud-failure
// behaviour callers expect.
func (c *Counter) Add(delta int64) {
	if delta < 0 {
		panic(fmt.Sprintf("metric: Counter.Add called with negative delta %d", delta))
	}
	pid := runtime_procPin()
	c.shards[pid&(shardCount-1)].v.Add(delta)
	runtime_procUnpin()
}

// Value returns the live cross-shard sum. Cheap (8 atomic loads),
// but not free — callers should not poll it on a hot path. Used by
// the flusher and by tests.
func (c *Counter) Value() int64 {
	var sum int64
	for i := range c.shards {
		sum += c.shards[i].v.Load()
	}
	return sum
}

// flush pushes the delta-since-last-flush into the underlying
// Prometheus counter. Called only by the registry's flusher.
func (c *Counter) flush() {
	sum := c.Value()
	if delta := sum - c.lastSent; delta > 0 {
		c.prom.Add(float64(delta))
		c.lastSent = sum
	}
}

// CounterVec is the label-bearing form of Counter. Per-tuple Counter
// pointers live in an immutable map behind an atomic.Pointer; reads
// are a single atomic load + map lookup, writes (rare) clone the map
// under a small mutex and CAS the pointer.
//
// First WithLabelValues call for a new tuple is slow (allocates +
// registers a Counter, clones the map). Subsequent calls are wait-
// free AND allocation-free for both single- and multi-label vectors
// (multi-label lookups borrow a buffer from a sync.Pool and use
// unsafe.String to view the encoded key without copying).
//
// For closed label sets (qtypes, rcodes, named outcomes), call
// Register at startup so the map never grows after init.
type CounterVec struct {
	promVec *prometheus.CounterVec

	// arity is the declared label-count of the underlying CounterVec.
	// We validate every WithLabelValues call against it so a bad-
	// arity call can't collide-hit an existing cached key. arity is
	// set once at construction; never mutated.
	arity int

	// m holds the current (key -> *Counter) map. Replaced wholesale
	// on writes via writeMu; readers atomic-load it without locks.
	m       atomic.Pointer[map[string]*Counter]
	writeMu sync.Mutex
}

// keyBufPool reuses byte buffers for multi-label key encoding so the
// hot-path WithLabelValues call doesn't allocate even with several
// labels. The pool's items are *[]byte (heap-stable across resets).
var keyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 64)
		return &b
	},
}

// NewCounterVec constructs a CounterVec, registers the underlying
// prometheus.CounterVec with reg (or prometheus.DefaultRegisterer
// when reg is nil), and starts the background flusher on first call.
func NewCounterVec(reg prometheus.Registerer, opts prometheus.CounterOpts, labels []string) *CounterVec {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	pv := prometheus.NewCounterVec(opts, labels)
	reg.MustRegister(pv)
	cv := &CounterVec{promVec: pv, arity: len(labels)}
	empty := map[string]*Counter{}
	cv.m.Store(&empty)
	ensureFlusher()
	return cv
}

// Register pre-creates the Counter for the given label tuple and
// returns it. Calling Register at boot for known label tuples avoids
// any map clone in steady state.
func (cv *CounterVec) Register(values ...string) *Counter {
	return cv.WithLabelValues(values...)
}

// WithLabelValues returns the sharded Counter for the given label
// tuple, creating one on first use. Panics on arity mismatch — same
// loud failure as prometheus.CounterVec.WithLabelValues; without
// this guard a bad-arity call could collide-hit an existing cached
// key and silently increment the wrong series.
//
// For single-label vectors, the call is allocation-free (uses
// values[0] directly as the map key). For multi-label vectors, the
// encoded key is built into a pooled buffer and viewed via
// unsafe.String for the lookup; if it hits, we return without any
// allocation. Only the cache-miss path materialises a real string
// for the map insert.
func (cv *CounterVec) WithLabelValues(values ...string) *Counter {
	if len(values) != cv.arity {
		panic(fmt.Sprintf("metric: WithLabelValues called with %d values, vec declared %d labels",
			len(values), cv.arity))
	}
	// Single-label fast path: the value is its own key, no encoding
	// needed (and length-prefix encoding would just be a waste here
	// since arity is fixed per-vec and validated above).
	if cv.arity == 1 {
		m := cv.m.Load()
		if c, ok := (*m)[values[0]]; ok {
			return c
		}
		return cv.create(values[0], values)
	}

	// Multi-label: encode into a pooled buffer using length-prefix
	// so no two distinct (v1, v2, ...) tuples can ever produce the
	// same bytes regardless of value content.
	pb := keyBufPool.Get().(*[]byte)
	*pb = encodeKey((*pb)[:0], values)

	// Alloc-free string view of the encoded bytes — valid only while
	// pb is checked out and unmodified. Used purely for the map
	// lookup, which neither retains nor mutates the key. The unsafe
	// is bounded: the resulting string never escapes this function
	// on the hit path, and on the miss path we materialise a real
	// string before releasing pb back to the pool.
	keyView := unsafe.String(unsafe.SliceData(*pb), len(*pb)) //nolint:gosec // see comment above

	m := cv.m.Load()
	if c, ok := (*m)[keyView]; ok {
		keyBufPool.Put(pb)
		return c
	}

	// Cache miss: copy the encoded bytes into a real string so it
	// stays valid after we return pb to the pool.
	realKey := string(*pb)
	keyBufPool.Put(pb)
	return cv.create(realKey, values)
}

func (cv *CounterVec) create(key string, values []string) *Counter {
	cv.writeMu.Lock()
	defer cv.writeMu.Unlock()

	// Re-check under the lock — another goroutine may have created
	// this tuple between our Load and our acquire of writeMu.
	cur := cv.m.Load()
	if c, ok := (*cur)[key]; ok {
		return c
	}

	promCounter := cv.promVec.WithLabelValues(values...)
	c := &Counter{prom: promCounter}

	// Enrol with the flush registry BEFORE making the counter
	// publicly findable via cv.m. If we published first, a brief
	// window exists where another goroutine could WithLabelValues +
	// Inc, while a concurrent FlushAll snapshot misses the not-yet-
	// registered counter — the increment would never reach
	// Prometheus, and at shutdown a final flush would drop it
	// silently. Counter.flush on an empty (un-incremented) counter
	// is a no-op, so a spuriously-early flush here is harmless.
	defaultRegistry.add(c)

	next := make(map[string]*Counter, len(*cur)+1)
	maps.Copy(next, *cur)
	next[key] = c
	cv.m.Store(&next)

	return c
}

// encodeKey writes a collision-free length-prefixed encoding of
// values into b and returns the extended slice. Each value is
// preceded by its uvarint length, so neither separator collisions
// nor arity collisions are possible: ("a\x1Fb",) and ("a", "b")
// encode to different byte sequences.
//
// The arity is fixed per-vec and validated before calling, so we
// don't need to encode it here.
func encodeKey(b []byte, values []string) []byte {
	var lenBuf [binary.MaxVarintLen64]byte
	for _, v := range values {
		n := binary.PutUvarint(lenBuf[:], uint64(len(v)))
		b = append(b, lenBuf[:n]...)
		b = append(b, v...)
	}
	return b
}

// Registry tracks every Counter so the flush goroutine can find them.
// There is exactly one default registry per process.
//
// mu guards the counters slice (write side: add; read side: snapshot
// inside flushAll). flushMu serialises flushAll itself — Counter.flush
// performs a read-modify-write on lastSent without atomics, so two
// concurrent flushes on the same counter would race on lastSent and
// could double-count or lose deltas. flushMu is taken for the whole
// flush pass; it's coarse but flushes run once per second at most.
type Registry struct {
	mu       sync.Mutex
	flushMu  sync.Mutex
	counters []*Counter
}

var defaultRegistry = &Registry{}

func (r *Registry) add(c *Counter) {
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
}

// flushAll snapshots the slice under r.mu, then runs flush on each
// counter under r.flushMu. The two locks are intentionally separate:
// mu must not be held while a Counter is flushing (the flush might
// allocate, and Prometheus' Add takes its own lock — holding mu
// across that would block new metric registrations). flushMu must
// be held across the whole pass to keep Counter.flush single-writer.
//
// Counters added mid-flush publish one interval late; that is fine.
func (r *Registry) flushAll() {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()

	r.mu.Lock()
	counters := append([]*Counter(nil), r.counters...)
	r.mu.Unlock()
	for _, c := range counters {
		c.flush()
	}
}

// FlushAll runs one flush of every registered counter. Useful at
// shutdown and in tests.
func FlushAll() { defaultRegistry.flushAll() }

// Flusher state — process-singleton, started lazily on the first
// NewCounter / NewCounterVec call so the package is impossible to
// use unsafely (a forgotten StartFlusher used to mean silent zeros
// on scrape, which is worse than any complexity).
//
// flusherInterval is the tick interval, configurable via
// SetFlushInterval before the flusher starts. Once started the
// interval is fixed for the goroutine's lifetime.
var (
	flusherInterval    = time.Second
	flusherIntervalMu  sync.Mutex
	flusherStartedOnce sync.Once
	flusherStopOnce    sync.Once
	flusherStarted     atomic.Bool
	flusherStop        chan struct{}
	flusherDone        chan struct{}
)

// SetFlushInterval overrides the default 1-second flush interval.
// Must be called BEFORE the first NewCounter / NewCounterVec; once
// the flusher goroutine is running its ticker is fixed. Panics on
// d <= 0 or if the flusher has already started.
func SetFlushInterval(d time.Duration) {
	if d <= 0 {
		panic(fmt.Sprintf("metric: SetFlushInterval requires d > 0, got %v", d))
	}
	flusherIntervalMu.Lock()
	defer flusherIntervalMu.Unlock()
	if flusherStarted.Load() {
		panic("metric: SetFlushInterval must be called before the first NewCounter / NewCounterVec")
	}
	flusherInterval = d
}

// ensureFlusher starts the background goroutine on first call.
// Idempotent — subsequent calls are no-ops. Called automatically
// by NewCounter and NewCounterVec.
//
// The interval read and the started transition both happen under
// flusherIntervalMu so SetFlushInterval can't slip between them:
// either it runs before the lock is taken (its update is observed),
// or it runs after Store(true) commits (it panics). It cannot
// "succeed too late" — return successfully while the goroutine
// silently uses the old interval. Channels are allocated BEFORE
// the lock so a concurrent Stop() that observes started=true
// always finds non-nil channels.
func ensureFlusher() {
	flusherStartedOnce.Do(func() {
		flusherStop = make(chan struct{})
		flusherDone = make(chan struct{})

		flusherIntervalMu.Lock()
		interval := flusherInterval
		flusherStarted.Store(true)
		flusherIntervalMu.Unlock()

		go func() {
			defer close(flusherDone)
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					defaultRegistry.flushAll()
				case <-flusherStop:
					defaultRegistry.flushAll()
					return
				}
			}
		}()
	})
}

// Stop drains the final flush and stops the background goroutine.
// Safe to call multiple times and from multiple goroutines
// concurrently; only the first call has effect. If the flusher
// never started (no counters were ever registered), Stop is a
// no-op.
//
// Callers MUST invoke Stop at shutdown — otherwise the last flush
// interval of counts is lost.
func Stop() {
	if !flusherStarted.Load() {
		return
	}
	flusherStopOnce.Do(func() {
		close(flusherStop)
		<-flusherDone
	})
}

// resetForTest clears registry + flusher state so a follow-up test
// starts from scratch. Tests only — never call from production code.
func resetForTest() {
	defaultRegistry.mu.Lock()
	defaultRegistry.counters = nil
	defaultRegistry.mu.Unlock()

	if flusherStarted.Load() {
		flusherStopOnce.Do(func() { close(flusherStop) })
		if flusherDone != nil {
			<-flusherDone
		}
	}
	flusherStop = nil
	flusherDone = nil
	flusherStarted.Store(false)
	flusherStartedOnce = sync.Once{}
	flusherStopOnce = sync.Once{}
	flusherIntervalMu.Lock()
	flusherInterval = time.Second
	flusherIntervalMu.Unlock()
}
