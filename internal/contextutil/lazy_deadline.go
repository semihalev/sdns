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

type lazyDeadlineCarrierKeyType struct{}

var lazyDeadlineCarrierKey = &lazyDeadlineCarrierKeyType{}

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
// request ID, NSEC3 hash memo); a pin that finds the table full falls back to
// an ordinary context.WithValue at the call site.
const lazyDeadlinePins = 4

// lazyDeadlinePin is one request-lifetime slot. The key is written under
// pinMu and published by the pin-count store, after which it never changes;
// lock-free readers see it only through the count's acquire load.
type lazyDeadlinePin struct {
	key   any
	value atomic.Value
}

// lazyDeadlineOverflow holds every pin beyond the first. It is allocated only
// when a second distinct key is pinned, so a request that pins one value — a
// terminal cache hit carries just the recursion-work ledger — pays no extra
// LazyDeadline footprint for the table.
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
	pinCount      atomic.Int32
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
	if key == lazyDeadlineCarrierKey {
		return c
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

// TrySetValueProvider installs provider directly on the LazyDeadline reachable
// through ctx. It returns false for ordinary contexts or when a provider was
// already installed.
func TrySetValueProvider(ctx context.Context, provider ValueProvider) bool {
	if ctx == nil || provider == nil {
		return false
	}
	lazy, _ := ctx.Value(lazyDeadlineCarrierKey).(*LazyDeadline)
	if lazy == nil {
		return false
	}

	lazy.pinMu.Lock()
	defer lazy.pinMu.Unlock()
	if lazy.valueProvider.Load() != nil {
		return false
	}
	lazy.valueProvider.Store(provider)
	return true
}

// TryPinValue stores one internal request-lifetime control value directly on
// the LazyDeadline reachable through ctx. The pin survives pooled metadata
// reuse without allocating a context.WithValue node. It is deliberately not
// exposed through Context.Value: callers must use PinnedValue, keeping the
// ordinary context value chain immutable. Re-pinning a key that is already
// pinned fails, as does pinning into a full table.
func TryPinValue(ctx context.Context, key, value any) bool {
	if ctx == nil || key == nil || value == nil {
		return false
	}
	lazy, _ := ctx.Value(lazyDeadlineCarrierKey).(*LazyDeadline)
	if lazy == nil {
		return false
	}

	lazy.pinMu.Lock()
	defer lazy.pinMu.Unlock()
	if lazy.pin(key) != nil {
		return false
	}
	n := lazy.pinCount.Load()
	if n == lazyDeadlinePins {
		return false
	}
	if n == 0 {
		lazy.pin0.key = key
		lazy.pin0.value.Store(value)
	} else {
		overflow := lazy.pinOverflow.Load()
		if overflow == nil {
			overflow = new(lazyDeadlineOverflow)
			// Published before the count store below, so a reader that
			// observes a count above one also observes this pointer.
			lazy.pinOverflow.Store(overflow)
		}
		overflow[n-1].key = key
		overflow[n-1].value.Store(value)
	}
	lazy.pinCount.Store(n + 1)
	return true
}

// PinnedValue returns the exact value stored in the LazyDeadline's
// request-lifetime slot for key. Unlike ctx.Value, it never falls through to
// a value provider or parent context.
func PinnedValue(ctx context.Context, key any) (any, bool) {
	if ctx == nil || key == nil {
		return nil, false
	}
	lazy, _ := ctx.Value(lazyDeadlineCarrierKey).(*LazyDeadline)
	if lazy == nil {
		return nil, false
	}
	if pin := lazy.pin(key); pin != nil {
		return pin.value.Load(), true
	}
	return nil, false
}

// pin returns the slot pinned under key, or nil. Safe without the lock: the
// pin-count store publishes each slot's key and the overflow pointer, and
// neither changes afterwards.
func (c *LazyDeadline) pin(key any) *lazyDeadlinePin {
	n := c.pinCount.Load()
	if n == 0 {
		return nil
	}
	if c.pin0.key == key {
		return &c.pin0
	}
	if n > 1 {
		overflow := c.pinOverflow.Load()
		for i := int32(0); i < n-1; i++ {
			if overflow[i].key == key {
				return &overflow[i]
			}
		}
	}
	return nil
}

// TryUpdatePinnedValueLocked computes and installs a replacement while holding
// the LazyDeadline's request-lifetime lock. It is intended for transitions
// whose initialization must complete before a concurrent request owner can
// close and recycle adjacent pooled state.
//
// update must be bounded and must not call the pin mutation APIs recursively
// on ctx (or a context derived from it): pinMu is deliberately non-reentrant.
// Cancellation methods use a separate lock, so update may safely inspect Done,
// Err or context.AfterFunc. The Locked suffix exposes the callback contract at
// each call site.
func TryUpdatePinnedValueLocked[T comparable](
	ctx context.Context,
	key any,
	old T,
	update func() T,
) (T, bool) {
	var zero T
	if ctx == nil || key == nil || update == nil {
		return zero, false
	}
	lazy, _ := ctx.Value(lazyDeadlineCarrierKey).(*LazyDeadline)
	if lazy == nil {
		return zero, false
	}

	lazy.pinMu.Lock()
	defer lazy.pinMu.Unlock()
	pin := lazy.pin(key)
	if pin == nil {
		return zero, false
	}
	current, typeOK := pin.value.Load().(T)
	if !typeOK || current != old {
		return current, false
	}
	value := update()
	pin.value.Store(value)
	return value, true
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
