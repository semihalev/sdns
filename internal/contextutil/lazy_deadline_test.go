package contextutil

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lazyDeadlineKey struct{}

type testValueProvider struct {
	key   any
	value any
}

func (p *testValueProvider) ContextValue(key any) (any, bool) {
	if key == p.key {
		return p.value, true
	}
	return nil, false
}

func TestLazyDeadlineFastPathDoesNotMaterialize(t *testing.T) {
	parent := context.WithValue(context.Background(), lazyDeadlineKey{}, "value")
	ctx := WithLazyTimeout(parent, time.Minute)

	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 {
		t.Fatalf("deadline = %v, %v; want a live deadline", deadline, ok)
	}
	if got := ctx.Value(lazyDeadlineKey{}); got != "value" {
		t.Fatalf("value = %v, want value", got)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if ctx.active.Load() != nil {
		t.Fatal("Deadline, Value or live Err materialized the context")
	}

	ctx.Cancel()
	if ctx.active.Load() != nil {
		t.Fatal("fast-path Cancel materialized the context")
	}
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("error after Cancel = %v, want context.Canceled", err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Done remained open after Cancel")
	}
}

func TestLazyDeadlineExpiresAfterDoneMaterializes(t *testing.T) {
	ctx := WithLazyTimeout(context.Background(), 20*time.Millisecond)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not close at the configured deadline")
	}
	if err := ctx.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	ctx.Cancel()
	if err := ctx.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Cancel replaced deadline error with %v", err)
	}
}

func TestLazyDeadlinePreservesParentCancellationAndCause(t *testing.T) {
	parent, cancelParent := context.WithCancelCause(context.Background())
	ctx := WithLazyTimeout(parent, time.Minute)
	cause := errors.New("transport closed")
	cancelParent(cause)

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not close Done")
	}
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := context.Cause(ctx); !errors.Is(got, cause) {
		t.Fatalf("cause = %v, want %v", got, cause)
	}
}

func TestLazyDeadlineLocalCancelPinsCauseBeforeParent(t *testing.T) {
	parent, cancelParent := context.WithCancelCause(context.Background())
	ctx := WithLazyTimeout(parent, time.Minute)
	ctx.Cancel()
	cancelParent(errors.New("later parent cause"))

	if got := context.Cause(ctx); !errors.Is(got, context.Canceled) {
		t.Fatalf("cause = %v, want context.Canceled", got)
	}
}

func TestLazyDeadlineCancelPreservesAlreadyCanceledParentCause(t *testing.T) {
	parent, cancelParent := context.WithCancelCause(context.Background())
	cause := errors.New("parent failed first")
	cancelParent(cause)

	ctx := WithLazyTimeout(parent, time.Minute)
	ctx.Cancel()

	if got := context.Cause(ctx); !errors.Is(got, cause) {
		t.Fatalf("cause = %v, want prior parent cause %v", got, cause)
	}
	if ctx.active.Load() == nil {
		t.Fatal("already-canceled parent did not materialize the cold cancellation path")
	}
}

func TestLazyDeadlineCarriesProviderAndInternalPinWithoutMaterializing(t *testing.T) {
	providerKey := &lazyDeadlineKey{}
	pinnedKey := new(int)
	ctx := WithLazyTimeout(context.Background(), time.Minute)
	wrapped := context.WithValue(ctx, lazyDeadlineKey{}, "outer")

	if !TrySetValueProvider(wrapped, &testValueProvider{key: providerKey, value: "provider"}) {
		t.Fatal("value provider was not installed through a value wrapper")
	}
	if !TryPinValue(wrapped, pinnedKey, "pinned") {
		t.Fatal("request-local value was not pinned through a value wrapper")
	}
	if got := wrapped.Value(providerKey); got != "provider" {
		t.Fatalf("provider value = %v, want provider", got)
	}
	if got := wrapped.Value(pinnedKey); got != nil {
		t.Fatalf("internal pin leaked through Context.Value: %v", got)
	}
	if got, ok := PinnedValue(wrapped, pinnedKey); !ok || got != "pinned" {
		t.Fatalf("exact pinned value = %v, %v; want pinned, true", got, ok)
	}
	value, updated := TryUpdatePinnedValueLocked(wrapped, pinnedKey, "pinned", func() string {
		return "replacement"
	})
	if !updated || value != "replacement" {
		t.Fatalf("matching pinned update = %q, %v; want replacement, true", value, updated)
	}
	if got := wrapped.Value(pinnedKey); got != nil {
		t.Fatalf("replaced internal pin leaked through Context.Value: %v", got)
	}
	value, updated = TryUpdatePinnedValueLocked(wrapped, pinnedKey, "pinned", func() string {
		return "stale"
	})
	if updated || value != "replacement" {
		t.Fatalf("stale pinned update = %q, %v; want replacement, false", value, updated)
	}
	if ctx.active.Load() != nil {
		t.Fatal("request-local values materialized the deadline context")
	}
	if TryPinValue(wrapped, pinnedKey, "again") {
		t.Fatal("re-pinning an already-pinned key unexpectedly succeeded")
	}
}

func TestLazyDeadlinePinTableHoldsDistinctKeysUpToItsBound(t *testing.T) {
	ctx := WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()

	keys := make([]*int, lazyDeadlinePins)
	for i := range keys {
		keys[i] = new(int)
		if !TryPinValue(ctx, keys[i], i) {
			t.Fatalf("pin %d of %d failed with free slots left", i+1, lazyDeadlinePins)
		}
	}
	if TryPinValue(ctx, new(int), "overflow") {
		t.Fatal("a pin beyond the table bound unexpectedly succeeded")
	}
	for i, key := range keys {
		got, ok := PinnedValue(ctx, key)
		if !ok || got != i {
			t.Fatalf("pin %d read back %v, %v; want %d, true", i, got, ok, i)
		}
	}

	// Each slot updates independently under its own key.
	value, updated := TryUpdatePinnedValueLocked(ctx, keys[1], 1, func() int { return 100 })
	if !updated || value != 100 {
		t.Fatalf("slot update = %v, %v; want 100, true", value, updated)
	}
	if got, _ := PinnedValue(ctx, keys[0]); got != 0 {
		t.Fatalf("neighbouring slot changed to %v", got)
	}
	if _, updated := TryUpdatePinnedValueLocked(ctx, new(int), 0, func() int { return 1 }); updated {
		t.Fatal("an update under an unpinned key unexpectedly succeeded")
	}
}

func TestLazyDeadlinePinnedValueAllocsNothing(t *testing.T) {
	ctx := WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()

	key := new(int)
	if !TryPinValue(ctx, key, "pinned") {
		t.Fatal("pin failed")
	}
	allocs := testing.AllocsPerRun(100, func() {
		if _, ok := PinnedValue(ctx, key); !ok {
			t.Fatal("pinned value lost")
		}
	})
	if allocs != 0 {
		t.Fatalf("PinnedValue allocated %.0f times per read, want 0", allocs)
	}
}

func TestLazyDeadlinePinnedUpdateMayInspectCancellation(t *testing.T) {
	ctx := WithLazyTimeout(context.Background(), time.Minute)
	key := new(int)
	if !TryPinValue(ctx, key, "pending") {
		t.Fatal("request-local value was not pinned")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		value, updated := TryUpdatePinnedValueLocked(ctx, key, "pending", func() string {
			_ = ctx.Done()
			_ = ctx.Err()
			stop := context.AfterFunc(ctx, func() {})
			_ = stop()
			return "active"
		})
		if !updated || value != "active" {
			t.Errorf("pinned update = %q, %v; want active, true", value, updated)
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pinned update deadlocked while inspecting cancellation")
	}
	ctx.Cancel()
}

func TestLazyDeadlineUsesEarlierParentDeadline(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelParent()
	ctx := WithLazyTimeout(parent, time.Minute)

	got, ok := ctx.Deadline()
	want, _ := parent.Deadline()
	if !ok || !got.Equal(want) {
		t.Fatalf("deadline = %v, %v; want parent deadline %v", got, ok, want)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("earlier parent deadline did not close Done")
	}
	if err := ctx.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestLazyDeadlineElapsedErrMaterializesAndPinsCause(t *testing.T) {
	ctx := WithLazyDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	if err := EffectiveError(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("effective error = %v, want context.DeadlineExceeded", err)
	}
	if ctx.active.Load() == nil {
		t.Fatal("elapsed Err did not materialize the deadline context")
	}
	ctx.Cancel()
	if err := ctx.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Cancel replaced elapsed deadline with %v", err)
	}
}

func TestLazyDeadlineAfterFuncStopAndFire(t *testing.T) {
	t.Run("stop", func(t *testing.T) {
		ctx := WithLazyTimeout(context.Background(), time.Minute)
		var calls atomic.Int32
		stop := context.AfterFunc(ctx, func() { calls.Add(1) })
		if !stop() {
			t.Fatal("stop returned false before cancellation")
		}
		ctx.Cancel()
		time.Sleep(10 * time.Millisecond)
		if got := calls.Load(); got != 0 {
			t.Fatalf("callback calls = %d, want 0", got)
		}
	})

	t.Run("fire", func(t *testing.T) {
		ctx := WithLazyTimeout(context.Background(), time.Minute)
		fired := make(chan struct{})
		_ = context.AfterFunc(ctx, func() { close(fired) })
		ctx.Cancel()
		select {
		case <-fired:
		case <-time.After(time.Second):
			t.Fatal("callback did not fire")
		}
	})
}

func TestLazyDeadlineCancelMaterializeRace(t *testing.T) {
	const iterations = 1000
	for range iterations {
		ctx := WithLazyTimeout(context.Background(), time.Minute)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = ctx.Done()
		}()
		go func() {
			defer wg.Done()
			<-start
			ctx.Cancel()
		}()
		close(start)
		wg.Wait()

		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("Done remained open after racing Cancel")
		}
		if err := ctx.Err(); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	}
}

func BenchmarkLazyDeadlineFastPath(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ctx := WithLazyTimeout(context.Background(), time.Second)
		_, _ = ctx.Deadline()
		if ctx.Err() != nil {
			b.Fatal("unexpected context error")
		}
		ctx.Cancel()
	}
}

func BenchmarkStandardDeadlineFastPath(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _ = ctx.Deadline()
		if ctx.Err() != nil {
			b.Fatal("unexpected context error")
		}
		cancel()
	}
}
