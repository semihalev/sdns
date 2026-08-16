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
type slabCache[T any] struct {
	mu   sync.Mutex
	idle []*T
}

// get pops an idle slab, or returns nil when the caller should allocate.
func (c *slabCache[T]) get() *T {
	c.mu.Lock()
	n := len(c.idle)
	if n == 0 {
		c.mu.Unlock()
		return nil
	}
	x := c.idle[n-1]
	c.idle[n-1] = nil
	c.idle = c.idle[:n-1]
	c.mu.Unlock()
	return x
}

// put parks a scrubbed slab for reuse.
func (c *slabCache[T]) put(x *T) {
	c.mu.Lock()
	c.idle = append(c.idle, x)
	c.mu.Unlock()
}

// trim drops every idle slab — backing array included, so nothing here
// keeps the burst alive — and reports how many went. The caller decides
// when trimming is worth a collection; this only makes the memory
// collectable.
func (c *slabCache[T]) trim() int {
	c.mu.Lock()
	n := len(c.idle)
	c.idle = nil
	c.mu.Unlock()
	return n
}

// size reports how many slabs are parked, for observability.
func (c *slabCache[T]) size() int {
	c.mu.Lock()
	n := len(c.idle)
	c.mu.Unlock()
	return n
}
