// Package inject provides the zerogate's negative controls: middleware
// that allocates on purpose, in the shapes the gate's attribution is
// weakest against.
//
// It lives outside the harness on purpose. The gate drops allocations
// made by its own measurement machinery — otherwise the profile snapshot
// would drown the traffic it is measuring — and a control that shared
// that package would be dropped along with it, which is exactly what
// happened the first time these were written inside the harness. Work
// that stands in for the server's must not look like the measurement's.
package inject

import (
	"context"
	"sync/atomic"

	"github.com/semihalev/sdns/middleware"
)

// Modes, selected by ZEROGATE_INJECT in the harness.
const (
	// ModeDeep allocates on the serving goroutine, at the bottom of a
	// call chain long enough that the engine's frames fall off the end of
	// a profile record. Attribution cannot tell what it was, so the exact
	// verdict has to refuse the unclassifiable stack rather than let it
	// through as residue.
	ModeDeep = "deep"

	// ModeTiny allocates a one-byte pointer-free object per query, which
	// is the shape Go's tiny allocator batches: sixteen of them share a
	// block, and only the block that opens a batch is ever profiled. It
	// is here to show that batching hides the count, not the cost — a
	// per-query tiny allocation still leaves a record every sixteenth
	// query, and the exact malloc counter sees every single one.
	ModeTiny = "tiny"

	// ModeAsync hands a token to a goroutine that is already running,
	// which allocates. Nothing allocates on the serving stack at all, so
	// attribution is blind by construction and the ops-relative verdict
	// is the only thing standing between this and a green run.
	ModeAsync = "async"
)

// Handler is the injecting middleware. It sits at the front of the chain.
type Handler struct{ mode string }

// New returns the injector for mode, or nil when mode is empty.
func New(mode string) *Handler {
	if mode == "" {
		return nil
	}
	if mode == ModeAsync {
		startAsyncSink()
	}
	return &Handler{mode: mode}
}

func (h *Handler) Name() string { return "zerogate-inject" }

func (h *Handler) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	switch h.mode {
	case ModeDeep:
		deepAlloc(48)
	case ModeTiny:
		tinyAlloc()
	case ModeAsync:
		select {
		case asyncWork <- struct{}{}:
		default:
		}
	}
	ch.Next(ctx)
}

// sink keeps the injected allocations reachable, so escape analysis
// cannot quietly make the control disappear.
var sink atomic.Pointer[[]byte]

//go:noinline
func deepAlloc(depth int) {
	if depth > 0 {
		deepAlloc(depth - 1)
		return
	}
	b := make([]byte, 32)
	sink.Store(&b)
}

// tinySink is byte-sized and pointer-free: the tiny allocator's own case.
var tinySink atomic.Pointer[byte]

//go:noinline
func tinyAlloc() {
	b := new(byte)
	*b = 1
	tinySink.Store(b)
}

var asyncWork = make(chan struct{}, 4096)

func startAsyncSink() {
	go func() {
		for range asyncWork {
			b := make([]byte, 32)
			sink.Store(&b)
		}
	}()
}
