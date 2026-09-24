package main

import (
	"context"
	"testing"
	"time"
)

// The walk budget reaches the savers as their context, and the process
// leaves at the exit limit even when a save never returns.
func TestPersistStateBounds(t *testing.T) {
	t.Run("the walk budget is the context", func(t *testing.T) {
		var deadline time.Time
		start := time.Now()
		persistState(func(ctx context.Context) {
			deadline, _ = ctx.Deadline()
		}, 200*time.Millisecond, time.Second)
		if d := deadline.Sub(start); d < 150*time.Millisecond || d > 400*time.Millisecond {
			t.Fatalf("savers were given %v, want the walk budget", d)
		}
	})

	t.Run("a save that hangs is left behind at the exit limit", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		start := time.Now()
		persistState(func(context.Context) { <-release }, 50*time.Millisecond, 200*time.Millisecond)
		if d := time.Since(start); d < 150*time.Millisecond || d > time.Second {
			t.Fatalf("returned after %v, want the exit limit", d)
		}
	})
}
