package contextutil

import (
	"context"
	"testing"
	"time"
)

type delayedDeadlineContext struct {
	deadline time.Time
}

func (c delayedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (delayedDeadlineContext) Done() <-chan struct{}         { return nil }
func (delayedDeadlineContext) Err() error                    { return nil }
func (delayedDeadlineContext) Value(any) any                 { return nil }

func TestEffectiveErrorSeesElapsedDeadlineBeforeContextTimer(t *testing.T) {
	ctx := delayedDeadlineContext{deadline: time.Now().Add(-time.Millisecond)}
	if err := EffectiveError(ctx); err != context.DeadlineExceeded {
		t.Fatalf("effective error = %v, want DeadlineExceeded", err)
	}
}

func TestEffectiveErrorPreservesPublishedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := EffectiveError(ctx); err != context.Canceled {
		t.Fatalf("effective error = %v, want Canceled", err)
	}
}

func TestEffectiveErrorLeavesLiveContextAlone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if err := EffectiveError(ctx); err != nil {
		t.Fatalf("effective error = %v, want nil", err)
	}
}
