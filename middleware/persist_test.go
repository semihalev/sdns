package middleware

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

type persistKey struct{}

// anchorHandler owns trust anchors, the resolver's role.
type anchorHandler struct{ n string }

func (h *anchorHandler) Name() string                            { return h.n }
func (h *anchorHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *anchorHandler) TrustAnchors() []dns.RR {
	rr, _ := dns.NewRR(". 3600 IN DNSKEY 257 3 13 AAAA")
	return []dns.RR{rr}
}

// stateHandler restores and persists, the cache's role, and records what it
// could see while doing so.
type stateHandler struct {
	n                 string
	anchors           func() []dns.RR
	restores          int
	readyWhileRestore bool
	anchorsAtRestore  bool
	persistedCtx      context.Context
}

func (h *stateHandler) Name() string                            { return h.n }
func (h *stateHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *stateHandler) SetTrustAnchors(a func() []dns.RR)       { h.anchors = a }
func (h *stateHandler) Restore() {
	h.restores++
	if h.restores == 1 {
		h.readyWhileRestore = Ready()
		h.anchorsAtRestore = h.anchors != nil && len(h.anchors()) == 1
	}
}
func (h *stateHandler) Persist(ctx context.Context) { h.persistedCtx = ctx }

// Setup restores after wiring and before publishing: the restore sees the
// trust anchors it depends on, and nothing that waits on Ready, the
// resolver's background upkeep or a query, can run while it does.
func TestSetupRestoresBeforePublishing(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	state := &stateHandler{n: "cache"}
	Register("cache", func(*config.Config) Handler { return state })
	Register("resolver", func(*config.Config) Handler { return &anchorHandler{n: "resolver"} })

	Setup(&config.Config{})

	if state.restores != 1 {
		t.Fatalf("Setup restored %d times, want once", state.restores)
	}
	if state.readyWhileRestore {
		t.Fatal("the pipeline was published while state was being restored")
	}
	if !state.anchorsAtRestore {
		t.Fatal("the restore ran before the trust anchors were wired")
	}
	if !Ready() {
		t.Fatal("Setup did not publish after restoring")
	}
}

func TestPersistReachesEveryPersister(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Persist(context.Background()) // before Setup: nothing to do, no panic

	state := &stateHandler{n: "cache"}
	Register("cache", func(*config.Config) Handler { return state })
	Setup(&config.Config{})

	ctx := context.WithValue(context.Background(), persistKey{}, 1)
	Persist(ctx)
	if state.persistedCtx != ctx {
		t.Fatal("Persist did not hand the context to the persister")
	}
}
