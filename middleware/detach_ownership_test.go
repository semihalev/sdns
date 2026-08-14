package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
)

// stashingHandler materializes its request and keeps the context, the way
// a handler that starts recursion keeps one while an upstream query is
// still unwinding.
type stashingHandler struct {
	ctx  context.Context
	meta *ResponseMeta
}

func (h *stashingHandler) Name() string { return "stashing" }

func (h *stashingHandler) ServeDNS(ctx context.Context, ch *Chain) {
	ctx, _ = ch.Materialize(ctx)
	h.ctx = ctx
	h.meta = ResponseMetaFrom(ctx)
	ch.Cancel()
}

// TestDetachedContextOutlivesTheSlab pins the ownership boundary at
// materialization.
//
// The meta a wire-born request starts on is a field of the transport
// job's Chain, so it is reset and handed to the next client the moment
// this one finishes. A context is not a value the request can call back:
// whoever still holds one after the handler returns would be reading —
// and, through the delegation cut, writing — whatever request owns the
// slab by then.
func TestDetachedContextOutlivesTheSlab(t *testing.T) {
	h := new(stashingHandler)
	ch := NewChain([]Handler{h})

	raw := packQuery(t, "detach.example.", dns.TypeA, false)
	req := new(Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	ch.ResetWire(mock.NewWriter("udp", "127.0.0.1:0"), req)

	// A bound folded in before the request leaves the byte path: the
	// state that must travel with it.
	cut := time.Now().Add(42 * time.Second)
	ch.Meta.BoundCut(cut)

	ch.Next(context.Background())
	ch.Finish()

	if h.meta == nil {
		t.Fatal("materialized context carries no ResponseMeta")
	}
	if h.meta == &ch.Meta {
		t.Fatal("the detached context points at the job's own meta; the next " +
			"request to take this slab shares state with the last one")
	}
	if got := h.meta.CutUntil(); !got.Equal(cut) {
		t.Fatalf("detached cut %v, want %v — state did not transfer", got, cut)
	}

	// The slab goes to the next client.
	next := packQuery(t, "other.example.", dns.TypeA, false)
	req2 := new(Request)
	if !req2.ParseWire(next, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	ch.ResetWire(mock.NewWriter("udp", "127.0.0.1:0"), req2)
	ch.Meta.BoundCut(time.Now().Add(time.Second))

	// What the first request held must be untouched by any of that.
	if got := h.meta.CutUntil(); !got.Equal(cut) {
		t.Fatalf("retained cut became %v after the slab was reused; want %v", got, cut)
	}
	if ResponseMetaFrom(h.ctx) == &ch.Meta {
		t.Fatal("retained context still resolves to the recycled meta")
	}
}
