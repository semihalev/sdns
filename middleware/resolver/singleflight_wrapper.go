package resolver

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// SingleflightWrapper wraps singleflight.Group with timeout tracking.
type SingleflightWrapper struct {
	group    singleflight.Group
	tracking sync.Map // key -> startTime
}

// NewSingleflightWrapper creates a new wrapper with periodic cleanup.
func NewSingleflightWrapper() *SingleflightWrapper {
	w := &SingleflightWrapper{}

	// Start cleanup goroutine
	go w.cleanupLoop()

	return w
}

// (*SingleflightWrapper).DoChan doChan wraps singleflight.DoChan with timeout tracking.
func (w *SingleflightWrapper) DoChan(key string, fn func() (any, error)) <-chan singleflight.Result {
	// Track when this key started
	w.tracking.Store(key, time.Now())

	// Call the underlying DoChan
	ch := w.group.DoChan(key, func() (any, error) {
		// Clean up tracking when done
		defer w.tracking.Delete(key)
		return fn()
	})

	return ch
}

// (*SingleflightWrapper).Forget forget wraps singleflight.Forget and cleans up tracking.
func (w *SingleflightWrapper) Forget(key string) {
	w.group.Forget(key)
	w.tracking.Delete(key)
}

// cleanupLoop periodically cleans up stuck queries.
func (w *SingleflightWrapper) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		w.cleanupStuckQueries()
	}
}

// cleanupStuckQueries removes queries that have been running too long.
func (w *SingleflightWrapper) cleanupStuckQueries() {
	now := time.Now()
	maxDuration := 15 * time.Second // Maximum time before considering a query stuck

	var stuckKeys []string

	// Find stuck queries
	w.tracking.Range(func(key, value any) bool {
		startTime, ok := value.(time.Time)
		if !ok {
			return true // Skip invalid entries
		}

		if now.Sub(startTime) > maxDuration {
			stuckKeys = append(stuckKeys, key.(string))
		}
		return true
	})

	// Forget stuck queries
	for _, key := range stuckKeys {
		w.Forget(key)
	}
}

// (*SingleflightWrapper).TimedDoChan timedDoChan executes a function
// with built-in timeout handling. The shared return reflects
// singleflight.Result.Shared — true when the caller received a value
// that was computed by another goroutine and may therefore be
// concurrently observed. Callers that mutate or rewrite the value
// (e.g. set a new message ID) should defensive-copy only when shared
// is true; uncontended callers can return the value directly.
func (w *SingleflightWrapper) TimedDoChan(ctx context.Context, key string, fn func() (any, error)) (val any, shared bool, err error) {
	val, shared, _, err = w.TimedDoChanWithRole(ctx, key, fn)
	return val, shared, err
}

// TimedDoChanWithRole is TimedDoChan plus a leader result. leader is true only
// for the caller whose closure actually ran; followers receive the shared
// result without executing their closure. Resolver policy errors use this bit
// to avoid leaking one request tree's exhausted budget into another.
func (w *SingleflightWrapper) TimedDoChanWithRole(ctx context.Context, key string, fn func() (any, error)) (val any, shared, leader bool, err error) {
	var ran atomic.Bool
	ch := w.DoChan(key, func() (any, error) {
		ran.Store(true)
		return fn()
	})

	select {
	case result := <-ch:
		return result.Val, result.Shared, ran.Load(), result.Err
	case <-ctx.Done():
		// Return promptly to this caller, but do not Forget the shared
		// generation. A canceling follower cannot safely identify which
		// generation it joined; deleting by key could erase a newer retry
		// group and split deduplication into parallel upstream work. The
		// running closure removes itself on completion, and cleanupLoop is
		// the bounded backstop for a genuinely stuck call.
		return nil, false, ran.Load(), ctx.Err()
	}
}
