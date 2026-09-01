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
	group singleflight.Group

	// generationMu serializes registration with Forget. The underlying
	// singleflight group protects its own map, but Forget works by key only;
	// without this wrapper-level ordering, cleanup for an old generation can
	// race with registration of its replacement and forget the new call.
	generationMu sync.Mutex
	current      map[string]*singleflightGeneration
	tracking     sync.Map // key -> *singleflightGeneration
}

// singleflightGeneration is also the generation token. Pointer identity lets
// an old leader remove only its own tracking record after cleanup has allowed
// a replacement leader to start for the same key.
type singleflightGeneration struct {
	started time.Time
}

// NewSingleflightWrapper creates a new wrapper with periodic cleanup.
func NewSingleflightWrapper() *SingleflightWrapper {
	w := &SingleflightWrapper{
		current: make(map[string]*singleflightGeneration),
	}

	// Start cleanup goroutine
	go w.cleanupLoop()

	return w
}

// (*SingleflightWrapper).DoChan doChan wraps singleflight.DoChan with timeout tracking.
func (w *SingleflightWrapper) DoChan(key string, fn func() (any, error)) <-chan singleflight.Result {
	w.generationMu.Lock()
	if w.current == nil {
		w.current = make(map[string]*singleflightGeneration)
	}
	generation := w.current[key]
	if generation == nil {
		generation = new(singleflightGeneration)
		w.current[key] = generation
	}
	ch := w.group.DoChan(key, func() (any, error) {
		// Only the closure selected by singleflight is a leader. Registering
		// here prevents hot followers from refreshing the stuck-call clock.
		w.generationMu.Lock()
		if w.current[key] == generation {
			generation.started = time.Now()
			w.tracking.Store(key, generation)
		}
		w.generationMu.Unlock()
		defer w.retireGeneration(key, generation)

		return fn()
	})
	w.generationMu.Unlock()

	return ch
}

// (*SingleflightWrapper).Forget forget wraps singleflight.Forget and cleans up tracking.
func (w *SingleflightWrapper) Forget(key string) {
	w.generationMu.Lock()
	defer w.generationMu.Unlock()

	generation := w.current[key]
	w.group.Forget(key)
	delete(w.current, key)
	if generation == nil {
		w.tracking.Delete(key)
		return
	}
	w.tracking.CompareAndDelete(key, generation)
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

	type stuckGeneration struct {
		key        string
		generation *singleflightGeneration
	}
	var stuck []stuckGeneration

	// Find stuck queries
	w.tracking.Range(func(key, value any) bool {
		keyString, keyOK := key.(string)
		generation, generationOK := value.(*singleflightGeneration)
		if !keyOK || !generationOK {
			return true // Skip invalid entries
		}

		if now.Sub(generation.started) > maxDuration {
			stuck = append(stuck, stuckGeneration{
				key:        keyString,
				generation: generation,
			})
		}
		return true
	})

	// Forget only the generation observed by the scan. A completed old leader
	// or a concurrent cleanup may already have made a replacement current.
	for _, candidate := range stuck {
		w.retireGeneration(candidate.key, candidate.generation)
	}
}

func (w *SingleflightWrapper) retireGeneration(key string, generation *singleflightGeneration) {
	w.generationMu.Lock()
	defer w.generationMu.Unlock()

	if w.current[key] == generation {
		// Forget before releasing the wrapper lock so the current token and
		// x/sync's key map move to the next generation together. The old
		// doCall checks its own call pointer and cannot remove a replacement.
		w.group.Forget(key)
		delete(w.current, key)
	}
	w.tracking.CompareAndDelete(key, generation)
}

// (*SingleflightWrapper).TimedDoChan timedDoChan executes a function
// with built-in timeout handling. The shared return reflects
// singleflight.Result.Shared, true when the caller received a value
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
