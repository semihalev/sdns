package server

import "sync"

// slabCache is the idle half of an engine's slab management: a plain,
// explicitly owned set of scrubbed jobs waiting to be reused.
//
// It is deliberately not a sync.Pool. A pool hands its contents to the
// collector's generational machinery, which is the wrong owner twice
// over: the collector may drop a warm cache the next cycle (a refill
// storm at the worst moment), and it may keep a cold one alive across
// two cycles (measured: after a burst, Put + one FreeOSMemory returned
// nothing to the OS, because the single GC it runs only moves the pool's
// primary set to its victim set). An explicit slice makes both moments
// ours: warm reuse survives any number of GC cycles, and trim — drop the
// references, then one FreeOSMemory — returns the burst deterministically
// with a single collection.
//
// The cache holds no authority. Admission is the engine's token or lease
// counter; this is only where the slabs those tokens paid for wait
// between requests. It never blocks: a miss means "allocate", trim means
// the next requests allocate again, and both are correctness-neutral.
//
// The idle set is sharded. A single mutex here was measured as the UDP
// engine's throughput ceiling: every request is one get and one put, so
// at wire speed the readers and all the workers convoyed on one lock —
// lock and scheduler overhead were a quarter of the CPU while the actual
// serving was single digits. Callers address a shard by hint (the reader
// or socket index); a job returns to the shard it was taken from, so
// steady-state traffic spreads as wide as the socket fan-out.
type slabCache[T any] struct {
	shards [slabShardCount]slabShard[T]
}

// slabShardCount is a power of two so the hint folds with a mask. Sized
// to the socket fan-out scale: contention drops by the shard count, and
// sixteen slices of idle slabs cost nothing over one.
const slabShardCount = 16

// slabShard pads to a cache line so neighboring shards' mutexes do not
// false-share under exactly the load the sharding exists for.
type slabShard[T any] struct {
	mu   sync.Mutex
	idle []*T
	_    [32]byte
}

// get pops an idle slab from the hinted shard, or returns nil when the
// caller should allocate. A miss does not search other shards: allocation
// is cheap, bounded by the engine's lease cap, and the put side refills
// this shard on the very next completion of its own traffic.
func (c *slabCache[T]) get(shard int) *T {
	s := &c.shards[shard&(slabShardCount-1)]
	s.mu.Lock()
	n := len(s.idle)
	if n == 0 {
		s.mu.Unlock()
		return nil
	}
	x := s.idle[n-1]
	s.idle[n-1] = nil
	s.idle = s.idle[:n-1]
	s.mu.Unlock()
	return x
}

// put parks a scrubbed slab for reuse on the hinted shard.
func (c *slabCache[T]) put(shard int, x *T) {
	s := &c.shards[shard&(slabShardCount-1)]
	s.mu.Lock()
	s.idle = append(s.idle, x)
	s.mu.Unlock()
}

// trim drops every idle slab — backing arrays included, so nothing here
// keeps the burst alive — and reports how many went. The caller decides
// when trimming is worth a collection; this only makes the memory
// collectable.
func (c *slabCache[T]) trim() int {
	total := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		total += len(s.idle)
		s.idle = nil
		s.mu.Unlock()
	}
	return total
}

// size reports how many slabs are parked, for observability.
func (c *slabCache[T]) size() int {
	total := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		total += len(s.idle)
		s.mu.Unlock()
	}
	return total
}
