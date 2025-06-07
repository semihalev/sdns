package resolver

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// SingleflightWrapper wraps singleflight.Group with timeout tracking
type SingleflightWrapper struct {
	group    singleflight.Group
	tracking sync.Map // key -> startTime
}

// NewSingleflightWrapper creates a new wrapper with periodic cleanup
func NewSingleflightWrapper() *SingleflightWrapper {
	w := &SingleflightWrapper{}

	// Start cleanup goroutine
	go w.cleanupLoop()

	return w
}

// DoChan wraps singleflight.DoChan with timeout tracking
func (w *SingleflightWrapper) DoChan(key string, fn func() (interface{}, error)) <-chan singleflight.Result {
	// Track when this key started
	w.tracking.Store(key, time.Now())

	// Call the underlying DoChan
	ch := w.group.DoChan(key, func() (interface{}, error) {
		// Clean up tracking when done
		defer w.tracking.Delete(key)
		return fn()
	})

	return ch
}

// Forget wraps singleflight.Forget and cleans up tracking
func (w *SingleflightWrapper) Forget(key string) {
	w.group.Forget(key)
	w.tracking.Delete(key)
}

// cleanupLoop periodically cleans up stuck queries
func (w *SingleflightWrapper) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		w.cleanupStuckQueries()
	}
}

// cleanupStuckQueries removes queries that have been running too long
func (w *SingleflightWrapper) cleanupStuckQueries() {
	now := time.Now()
	maxDuration := 15 * time.Second // Maximum time before considering a query stuck

	var stuckKeys []string

	// Find stuck queries
	w.tracking.Range(func(key, value interface{}) bool {
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

// TimedDoChan executes a function with built-in timeout handling
func (w *SingleflightWrapper) TimedDoChan(ctx context.Context, key string, fn func() (interface{}, error)) (interface{}, error) {
	ch := w.DoChan(key, fn)

	select {
	case result := <-ch:
		return result.Val, result.Err
	case <-ctx.Done():
		// Context cancelled/timed out - forget the key
		w.Forget(key)
		return nil, ctx.Err()
	}
}
