package contextutil_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/semihalev/sdns/internal/contextutil"
)

// jobCarrier is a minimal external Carrier implementation, shaped like the
// server's future job carrier: plain mutex-guarded slots, resettable, no
// Done channel. Living in an external test package, it proves the Carrier
// contract is implementable with exported API alone.
type jobCarrier struct {
	deadline time.Time

	mu       sync.Mutex
	keys     [4]any
	values   [4]any
	provider contextutil.ValueProvider
}

func (j *jobCarrier) Deadline() (time.Time, bool) { return j.deadline, true }
func (j *jobCarrier) Done() <-chan struct{}       { return nil }
func (j *jobCarrier) Err() error                  { return nil }

func (j *jobCarrier) Value(key any) any {
	if v, ok := contextutil.CarrierLookup(j, key); ok {
		return v
	}
	j.mu.Lock()
	provider := j.provider
	j.mu.Unlock()
	if provider != nil {
		if v, ok := provider.ContextValue(key); ok {
			return v
		}
	}
	return nil
}

func (j *jobCarrier) TryPin(key, value any) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	free := -1
	for i := range j.keys {
		if j.keys[i] == key {
			return false
		}
		if j.keys[i] == nil && free < 0 {
			free = i
		}
	}
	if free < 0 {
		return false
	}
	j.keys[free] = key
	j.values[free] = value
	return true
}

func (j *jobCarrier) Pinned(key any) (any, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.keys {
		if j.keys[i] == key {
			return j.values[i], true
		}
	}
	return nil, false
}

func (j *jobCarrier) UpdatePinLocked(key any, update func(any) (any, bool)) (any, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.keys {
		if j.keys[i] != key {
			continue
		}
		next, ok := update(j.values[i])
		if !ok || next == nil {
			return j.values[i], false
		}
		j.values[i] = next
		return next, true
	}
	return nil, false
}

func (j *jobCarrier) TrySetProvider(p contextutil.ValueProvider) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.provider != nil {
		return false
	}
	j.provider = p
	return true
}

// reset models job recycling between requests.
func (j *jobCarrier) reset() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.keys = [4]any{}
	j.values = [4]any{}
	j.provider = nil
}

type extProvider struct{ key, value any }

func (p extProvider) ContextValue(key any) (any, bool) {
	if key == p.key {
		return p.value, true
	}
	return nil, false
}

// TestExternalCarrierWorksThroughPackageHelpers pins the generalization the
// job carrier depends on: every package-level pin/provider helper must work
// identically on a foreign Carrier implementation, found through arbitrary
// context wrapping, with LazyDeadline semantics.
func TestExternalCarrierWorksThroughPackageHelpers(t *testing.T) {
	job := &jobCarrier{deadline: time.Now().Add(time.Second)}
	// Wrap so discovery must go through Value, as it does in the chain.
	ctx := context.WithValue(context.Context(job), extProvider{}, "wrapper")

	key := new(int)
	if !contextutil.TryPinValue(ctx, key, "first") {
		t.Fatal("pin through a wrapped external carrier failed")
	}
	if contextutil.TryPinValue(ctx, key, "again") {
		t.Fatal("re-pin unexpectedly succeeded")
	}
	if got, ok := contextutil.PinnedValue(ctx, key); !ok || got != "first" {
		t.Fatalf("pinned read = %v, %v", got, ok)
	}

	value, ok := contextutil.TryUpdatePinnedValueLocked(ctx, key, "first", func() string {
		return "second"
	})
	if !ok || value != "second" {
		t.Fatalf("matching update = %v, %v; want second, true", value, ok)
	}
	value, ok = contextutil.TryUpdatePinnedValueLocked(ctx, key, "first", func() string {
		return "stale"
	})
	if ok || value != "second" {
		t.Fatalf("stale update = %v, %v; want second, false", value, ok)
	}

	providerKey := new(int)
	if !contextutil.TrySetValueProvider(ctx, extProvider{key: providerKey, value: "provided"}) {
		t.Fatal("provider install failed")
	}
	if contextutil.TrySetValueProvider(ctx, extProvider{}) {
		t.Fatal("second provider install unexpectedly succeeded")
	}
	if got := ctx.Value(providerKey); got != "provided" {
		t.Fatalf("provider value through carrier = %v", got)
	}
	if contextutil.CarrierFrom(ctx) != contextutil.Carrier(job) {
		t.Fatal("CarrierFrom did not resolve the wrapped carrier")
	}

	// Recycling clears everything; the helpers must see a fresh carrier.
	job.reset()
	if _, ok := contextutil.PinnedValue(ctx, key); ok {
		t.Fatal("pin survived carrier reset")
	}
	if !contextutil.TryPinValue(ctx, key, "next-request") {
		t.Fatal("pin after reset failed")
	}
}

// TestLazyDeadlineImplementsCarrier pins that the ordinary request context
// satisfies the same interface, so both paths share one contract.
func TestLazyDeadlineImplementsCarrier(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Second)
	defer lazy.Cancel()

	var carrier contextutil.Carrier = lazy
	if got := contextutil.CarrierFrom(lazy); got != carrier {
		t.Fatal("LazyDeadline not discoverable as a Carrier")
	}
	key := new(int)
	if !carrier.TryPin(key, 7) {
		t.Fatal("direct TryPin failed")
	}
	if got, ok := carrier.Pinned(key); !ok || got != 7 {
		t.Fatalf("direct Pinned = %v, %v", got, ok)
	}
}
