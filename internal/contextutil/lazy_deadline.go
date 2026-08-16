package contextutil

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	lazyDeadlineLive uint32 = iota
	lazyDeadlineCanceled
	lazyDeadlineExceeded
)

var lazyDeadlineClosed = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// ValueProvider supplies request-local context values without adding another
// context.WithValue wrapper to a LazyDeadline. Providers are installed before
// the context is published to middleware and must be safe for concurrent use.
type ValueProvider interface {
	ContextValue(key any) (value any, ok bool)
}

type lazyDeadlineHolder struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// LazyDeadline is a request context whose absolute deadline is visible
// immediately, but whose timer and parent-cancellation registration are
// materialized only when a caller needs Done or AfterFunc.
//
// This keeps terminal cache hits off context.WithDeadline's allocation path
// while preserving the same deadline for cache misses, child contexts and
// blocking transport operations. A LazyDeadline must not be reused across
// requests: child contexts and cancellation callbacks may retain it.
// lazyDeadlinePins bounds the request-lifetime value slots. The size mirrors
// the in-tree pinners (recursion-work ledger, resolution-attempt guard,
// request ID, NSEC3 hash memo, client-ECS marker); a pin that finds the
// table full falls back to an ordinary context.WithValue at the call site.
// The inventory once said four and left the ECS marker out, so every
// ECS-marked miss overflowed the table and the last pinner — the NSEC3
// memo — lost exactly the cross-subquery sharing pinning exists for.
const lazyDeadlinePins = 5

// lazyDeadlinePin is one request-lifetime slot. The non-nil value is both
// the occupancy sentinel and the publication barrier: the key is written
// first, under pinMu, and becomes visible through the value's release store.
// A reader may look at a slot's key only after observing a non-nil value.
// Pinned values are never a bare nil interface (TryPinValue rejects it), so
// an occupied slot cannot read as free.
type lazyDeadlinePin struct {
	key   any
	value atomic.Value
}

// match reports whether the slot is occupied under key, in the only order
// the publication protocol allows.
func (p *lazyDeadlinePin) match(key any) bool {
	return p.value.Load() != nil && p.key == key
}

// lazyDeadlineOverflow holds every pin beyond the first. It is allocated only
// when a second distinct key is pinned, so a request that pins one value — a
// terminal cache hit carries just the recursion-work ledger — keeps the
// LazyDeadline in its original size and allocation class (gated by test).
type lazyDeadlineOverflow [lazyDeadlinePins - 1]lazyDeadlinePin

type LazyDeadline struct {
	parent   context.Context
	deadline time.Time

	mu     sync.Mutex
	pinMu  sync.Mutex
	state  atomic.Uint32
	active atomic.Pointer[lazyDeadlineHolder]

	valueProvider atomic.Value
	pin0          lazyDeadlinePin
	pinOverflow   atomic.Pointer[lazyDeadlineOverflow]
}

// WithLazyTimeout returns a LazyDeadline whose deadline is no later than the
// parent's. Call Cancel when the request finishes.
func WithLazyTimeout(parent context.Context, timeout time.Duration) *LazyDeadline {
	return WithLazyDeadline(parent, time.Now().Add(timeout))
}

// WithLazyDeadline returns a LazyDeadline with the earlier of deadline and
// the parent's deadline. Call Cancel when the request finishes.
func WithLazyDeadline(parent context.Context, deadline time.Time) *LazyDeadline {
	if parent == nil {
		panic("cannot create context from nil parent")
	}
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	return &LazyDeadline{parent: parent, deadline: deadline}
}

// Deadline implements context.Context.
func (c *LazyDeadline) Deadline() (time.Time, bool) {
	return c.deadline, true
}

// Done implements context.Context. Its first live call materializes the
// standard-library deadline context so timer and parent cancellation semantics
// remain identical on paths that actually block.
func (c *LazyDeadline) Done() <-chan struct{} {
	active := c.materialize()
	if active == nil {
		return lazyDeadlineClosed
	}
	return active.ctx.Done()
}

// Err implements context.Context. A parent cancellation or elapsed deadline
// materializes the standard context to pin the first terminal cause.
func (c *LazyDeadline) Err() error {
	if active := c.active.Load(); active != nil {
		return active.ctx.Err()
	}
	if err := c.localError(); err != nil {
		return err
	}
	if c.parent.Err() == nil && time.Now().Before(c.deadline) {
		return nil
	}
	if active := c.materialize(); active != nil {
		return active.ctx.Err()
	}
	return c.localError()
}

// Value implements context.Context. Once materialized, values are deliberately
// routed through the standard child context. Besides preserving values, this
// lets context.WithCancel/WithDeadline recognize its private parent fast path
// instead of spawning a propagation goroutine.
func (c *LazyDeadline) Value(key any) any {
	if v, ok := CarrierLookup(c, key); ok {
		return v
	}
	if provider, _ := c.valueProvider.Load().(ValueProvider); provider != nil {
		if value, ok := provider.ContextValue(key); ok {
			return value
		}
	}
	if active := c.active.Load(); active != nil {
		return active.ctx.Value(key)
	}
	if c.state.Load() != lazyDeadlineLive {
		// Suppress the parent's private cancellation identity after a local
		// fast-path Cancel. Otherwise context.Cause could later report a
		// parent cause that happened after this context was already canceled.
		if c.parent.Done() == nil {
			return c.parent.Value(key)
		}
		return context.WithoutCancel(c.parent).Value(key)
	}
	return c.parent.Value(key)
}

// TrySetProvider implements Carrier. A second install fails.
func (c *LazyDeadline) TrySetProvider(provider ValueProvider) bool {
	if provider == nil {
		return false
	}
	c.pinMu.Lock()
	defer c.pinMu.Unlock()
	if c.valueProvider.Load() != nil {
		return false
	}
	c.valueProvider.Store(provider)
	return true
}

// TryPin implements Carrier. Re-pinning a key that is already pinned fails,
// as does pinning into a full table.
func (c *LazyDeadline) TryPin(key, value any) bool {
	if key == nil || value == nil {
		return false
	}
	c.pinMu.Lock()
	defer c.pinMu.Unlock()
	if c.pin(key) != nil {
		return false
	}
	if c.pin0.value.Load() == nil {
		c.pin0.key = key
		c.pin0.value.Store(value)
		return true
	}
	overflow := c.pinOverflow.Load()
	if overflow == nil {
		// Safe to publish empty: every slot reads as free until its value
		// store, which is what publishes the slot's key.
		overflow = new(lazyDeadlineOverflow)
		c.pinOverflow.Store(overflow)
	}
	for i := range overflow {
		if overflow[i].value.Load() == nil {
			overflow[i].key = key
			overflow[i].value.Store(value)
			return true
		}
	}
	return false
}

// Pinned implements Carrier: it returns the exact value stored in the
// request-lifetime slot for key, lock-free.
func (c *LazyDeadline) Pinned(key any) (any, bool) {
	if key == nil {
		return nil, false
	}
	if pin := c.pin(key); pin != nil {
		return pin.value.Load(), true
	}
	return nil, false
}

// pin returns the slot pinned under key, or nil. Safe without the lock: an
// occupied slot's key was published by its value store and neither changes
// afterwards.
func (c *LazyDeadline) pin(key any) *lazyDeadlinePin {
	if c.pin0.match(key) {
		return &c.pin0
	}
	if overflow := c.pinOverflow.Load(); overflow != nil {
		for i := range overflow {
			if overflow[i].match(key) {
				return &overflow[i]
			}
		}
	}
	return nil
}

// UpdatePinLocked implements Carrier: update runs with the current slot
// value while pinMu is held, and its return value is stored when ok. See
// the Carrier contract for the reentrancy and non-nil rules.
func (c *LazyDeadline) UpdatePinLocked(
	key any,
	update func(current any) (next any, ok bool),
) (any, bool) {
	if key == nil || update == nil {
		return nil, false
	}
	c.pinMu.Lock()
	defer c.pinMu.Unlock()
	pin := c.pin(key)
	if pin == nil {
		return nil, false
	}
	current := pin.value.Load()
	next, ok := update(current)
	if !ok {
		return current, false
	}
	if next == nil {
		return current, false
	}
	pin.value.Store(next)
	return next, true
}

// UpdatePinTransitionLocked implements Carrier; see the interface
// contract. The body mirrors UpdatePinLocked with the transition on an
// interface instead of a closure.
func (c *LazyDeadline) UpdatePinTransitionLocked(key any, t PinTransition) (any, bool) {
	if key == nil || t == nil {
		return nil, false
	}
	c.pinMu.Lock()
	defer c.pinMu.Unlock()
	pin := c.pin(key)
	if pin == nil {
		return nil, false
	}
	current := pin.value.Load()
	next, ok := t.NextLocked(current)
	if !ok || next == nil {
		return current, false
	}
	pin.value.Store(next)
	return next, true
}

// Cancel releases an armed timer/parent registration, or records a terminal
// cause without arming one when the request completed on the fast path.
func (c *LazyDeadline) Cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if active := c.active.Load(); active != nil {
		active.cancel()
		return
	}
	if c.state.Load() != lazyDeadlineLive {
		return
	}

	parentErr := c.parent.Err()
	if parentErr != nil {
		// A standard deadline child inherits the parent's first cancellation
		// cause. Materialize this cold path before recording a local terminal
		// state so context.Cause remains independent of observation order.
		c.active.Store(c.materializeLocked())
		return
	}
	switch {
	case !time.Now().Before(c.deadline):
		c.state.Store(lazyDeadlineExceeded)
	default:
		c.state.Store(lazyDeadlineCanceled)
	}
}

func (c *LazyDeadline) materialize() *lazyDeadlineHolder {
	if active := c.active.Load(); active != nil {
		return active
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if active := c.active.Load(); active != nil {
		return active
	}
	if c.state.Load() != lazyDeadlineLive {
		return nil
	}

	active := c.materializeLocked()
	c.active.Store(active)
	return active
}

func (c *LazyDeadline) materializeLocked() *lazyDeadlineHolder {
	ctx, cancel := context.WithDeadline(c.parent, c.deadline) //nolint:gosec // G118: Cancel stores and releases this lazily armed context
	return &lazyDeadlineHolder{ctx: ctx, cancel: cancel}
}

func (c *LazyDeadline) localError() error {
	switch c.state.Load() {
	case lazyDeadlineCanceled:
		return context.Canceled
	case lazyDeadlineExceeded:
		return context.DeadlineExceeded
	default:
		return nil
	}
}
