package contextutil

import "context"

// Carrier is the request-lifetime anchor a context exposes: the pin table
// and the value provider that request-scoped machinery (response metadata,
// recursion-work accounting, the resolution-attempt guard, caches' memo
// state) rides on without deriving value contexts.
//
// Two implementations exist by design: *LazyDeadline, the ordinary request
// context, and the server's job carrier, which serves the allocation-free
// fast path and is recycled between requests. Everything that pins or reads
// request-lifetime values goes through the package-level helpers
// (TryPinValue, PinnedValue, TryUpdatePinnedValueLocked,
// TrySetValueProvider), which resolve the carrier from the context and work
// identically on either implementation.
//
// Contract for implementers:
//   - TryPin stores value under key exactly once; re-pinning a key that is
//     already pinned fails, as does pinning into a full table. key and value
//     are never nil interfaces.
//   - Pinned returns the exact stored value. It must be safe under the
//     implementation's declared concurrency (LazyDeadline: lock-free
//     readers; the job carrier: single-owner with a cheap lock).
//   - UpdatePinLocked calls update with the current value while holding the
//     carrier's pin lock and stores the returned value when ok. update must
//     be bounded and must not call the pin APIs recursively on the same
//     carrier; the lock is deliberately non-reentrant. The stored value must
//     not be a nil interface. When the slot is missing it returns (nil,
//     false); when update declines it returns (current, false).
//   - TrySetProvider installs the value provider once; a second install
//     fails.
type Carrier interface {
	context.Context

	TryPin(key, value any) bool
	Pinned(key any) (any, bool)
	UpdatePinLocked(key any, update func(current any) (next any, ok bool)) (any, bool)

	// UpdatePinTransitionLocked is UpdatePinLocked with the transition
	// carried as an interface value instead of a closure. A closure
	// forces its captures to the heap at every call site; a transition
	// implemented on state the caller already owns rides its existing
	// pointer and costs nothing. Same lock, same reentrancy and non-nil
	// rules.
	UpdatePinTransitionLocked(key any, t PinTransition) (any, bool)
	TrySetProvider(provider ValueProvider) bool
}

type carrierKeyType struct{}

// carrierKey is how the package-level helpers find the carrier through an
// arbitrarily wrapped context. It stays unexported: implementations answer
// it by delegating their Value lookups to CarrierLookup.
var carrierKey = &carrierKeyType{}

// CarrierFrom returns the carrier reachable through ctx, or nil.
func CarrierFrom(ctx context.Context) Carrier {
	if ctx == nil {
		return nil
	}
	carrier, _ := ctx.Value(carrierKey).(Carrier)
	return carrier
}

// CarrierLookup answers the carrier-discovery key on behalf of an
// implementation: a Carrier's Value method delegates to it before its own
// lookups, so the package-level helpers can find the carrier through any
// number of derived contexts.
func CarrierLookup(c Carrier, key any) (any, bool) {
	if key == carrierKey {
		return c, true
	}
	return nil, false
}

// TryPinValue stores one request-lifetime control value directly on the
// carrier reachable through ctx. The pin survives pooled metadata reuse
// without allocating a context.WithValue node. It is deliberately not
// exposed through Context.Value: callers must use PinnedValue, keeping the
// ordinary context value chain immutable. Re-pinning a key that is already
// pinned fails, as does pinning into a full table.
func TryPinValue(ctx context.Context, key, value any) bool {
	if key == nil || value == nil {
		return false
	}
	carrier := CarrierFrom(ctx)
	if carrier == nil {
		return false
	}
	return carrier.TryPin(key, value)
}

// PinnedValue returns the exact value stored in the carrier's
// request-lifetime slot for key. Unlike ctx.Value, it never falls through
// to a value provider or parent context.
func PinnedValue(ctx context.Context, key any) (any, bool) {
	if key == nil {
		return nil, false
	}
	carrier := CarrierFrom(ctx)
	if carrier == nil {
		return nil, false
	}
	return carrier.Pinned(key)
}

// PinTransition computes a pinned value's replacement while the pin lock
// is held. NextLocked follows UpdatePinLocked's callback contract: it
// must be bounded, must not touch the pin APIs reentrantly, and a false
// return leaves the current value in place.
type PinTransition interface {
	NextLocked(current any) (next any, ok bool)
}

// UpdatePinnedTransitionLocked runs t against the carrier reachable
// through ctx. It exists for hot transitions: the closure-based
// TryUpdatePinnedValueLocked allocates its adapter and captures on every
// call, which a live profile priced at two objects per materialized
// request.
func UpdatePinnedTransitionLocked(ctx context.Context, key any, t PinTransition) (any, bool) {
	if key == nil || t == nil {
		return nil, false
	}
	carrier := CarrierFrom(ctx)
	if carrier == nil {
		return nil, false
	}
	return carrier.UpdatePinTransitionLocked(key, t)
}

// TryUpdatePinnedValueLocked computes and installs a replacement while
// holding the carrier's request-lifetime lock. It is intended for
// transitions whose initialization must complete before a concurrent
// request owner can close and recycle adjacent pooled state.
//
// update must be bounded and must not call the pin mutation APIs
// recursively on ctx (or a context derived from it): the pin lock is
// deliberately non-reentrant. Cancellation methods use separate locks, so
// update may safely inspect Done, Err or context.AfterFunc. The Locked
// suffix exposes the callback contract at each call site.
func TryUpdatePinnedValueLocked[T comparable](
	ctx context.Context,
	key any,
	old T,
	update func() T,
) (T, bool) {
	var zero T
	if key == nil || update == nil {
		return zero, false
	}
	carrier := CarrierFrom(ctx)
	if carrier == nil {
		return zero, false
	}
	value, ok := carrier.UpdatePinLocked(key, func(current any) (any, bool) {
		typed, typeOK := current.(T)
		if !typeOK || typed != old {
			return nil, false
		}
		return update(), true
	})
	if !ok {
		typed, _ := value.(T)
		return typed, false
	}
	typed, _ := value.(T)
	return typed, true
}

// TrySetValueProvider installs provider on the carrier reachable through
// ctx. It returns false for ordinary contexts or when a provider was
// already installed.
func TrySetValueProvider(ctx context.Context, provider ValueProvider) bool {
	if provider == nil {
		return false
	}
	carrier := CarrierFrom(ctx)
	if carrier == nil {
		return false
	}
	return carrier.TrySetProvider(provider)
}
