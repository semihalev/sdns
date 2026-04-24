package middleware

import (
	"sync/atomic"

	"github.com/semihalev/sdns/config"
)

// Pipeline is the compiled, immutable middleware chain produced by
// Registry.Build. All fields are set at construction time and never
// mutated, so every read is safe without synchronization.
type Pipeline struct {
	handlers []Handler
	byName   map[string]Handler
	names    []string // full registered name list, including disabled
}

// Handlers returns the enabled handlers in chain order. The returned slice
// aliases Pipeline's internal storage; callers must not mutate it.
func (p *Pipeline) Handlers() []Handler {
	if p == nil {
		return nil
	}
	return p.handlers
}

// Get returns the enabled handler with the given name or nil if the
// middleware is not registered or is disabled for the current config.
func (p *Pipeline) Get(name string) Handler {
	if p == nil {
		return nil
	}
	return p.byName[name]
}

// List returns every registered middleware name in order, including
// disabled ones. Useful for diagnostics.
func (p *Pipeline) List() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.names))
	copy(out, p.names)
	return out
}

// SubPipeline returns a new Pipeline containing the same handlers in
// the same order, minus any whose Name() is listed in skip. Used to
// build the internal sub-pipeline for queryer.Queryer: client-only
// guards (metrics, dnstap, accesslist, ratelimit, reflex, accesslog,
// loop) are dropped so internal sub-queries don't pollute
// observability or double-count against rate limits, but local-answer
// middlewares (hostsfile, blocklist, kubernetes, as112), cache,
// failover, and resolver/forwarder stay.
//
// The returned Pipeline is independent of the receiver — it has its
// own byName index and handler slice. The names list carries forward
// the full registered list for diagnostics.
func (p *Pipeline) SubPipeline(skip ...string) *Pipeline {
	if p == nil {
		return nil
	}
	skipSet := make(map[string]struct{}, len(skip))
	for _, n := range skip {
		skipSet[n] = struct{}{}
	}
	handlers := make([]Handler, 0, len(p.handlers))
	byName := make(map[string]Handler, len(p.handlers))
	for _, h := range p.handlers {
		if _, drop := skipSet[h.Name()]; drop {
			continue
		}
		handlers = append(handlers, h)
		byName[h.Name()] = h
	}
	return &Pipeline{handlers: handlers, byName: byName, names: p.names}
}

// NewChain returns a fresh Chain bound to this pipeline's handlers.
// Used by queryer.Queryer to dispatch an internal request through
// the sub-pipeline without pulling from the production chainPool
// (which is tied to the full pipeline).
func (p *Pipeline) NewChain() *Chain {
	if p == nil {
		return nil
	}
	return NewChain(p.handlers)
}

// Purgers returns every enabled handler that implements Purger, in
// pipeline order. The api purge endpoint iterates this to invalidate
// both the cache middleware's entries and the resolver handler's
// nameserver cache.
func (p *Pipeline) Purgers() []Purger {
	if p == nil {
		return nil
	}
	out := make([]Purger, 0, len(p.handlers))
	for _, h := range p.handlers {
		if pr, ok := h.(Purger); ok {
			out = append(out, pr)
		}
	}
	return out
}

// globalPipeline holds the active Pipeline. Reads on the hot path are
// atomic and lock-free; writes happen only once, from Setup.
var (
	globalPipeline atomic.Pointer[Pipeline]
	setupDone      atomic.Bool
)

// Setup builds the DefaultRegistry against cfg, loads external plugins,
// and publishes the resulting Pipeline globally. It panics if called more
// than once without an intervening Reset.
func Setup(cfg *config.Config) {
	if !setupDone.CompareAndSwap(false, true) {
		panic("middleware: Setup already called")
	}
	DefaultRegistry.loadPlugins(cfg)
	globalPipeline.Store(DefaultRegistry.Build(cfg))
}

// Ready reports whether Setup has completed.
func Ready() bool {
	return globalPipeline.Load() != nil
}

// GlobalPipeline returns the active pipeline snapshot, or nil before
// Setup. Startup wiring (queryer construction, api purge hooks) reads
// this once to derive sub-pipelines and enumerate purgers.
func GlobalPipeline() *Pipeline {
	return globalPipeline.Load()
}

// Handlers returns the enabled handlers from the global Pipeline. Returns
// nil before Setup.
func Handlers() []Handler {
	return globalPipeline.Load().Handlers()
}

// Get returns an enabled handler by name from the global Pipeline. Returns
// nil before Setup or if the middleware is disabled / unknown.
func Get(name string) Handler {
	return globalPipeline.Load().Get(name)
}

// List returns every registered middleware name in insertion order,
// including disabled ones. Before Setup it returns names from the
// DefaultRegistry; after Setup it returns the snapshot captured at Build.
func List() []string {
	if p := globalPipeline.Load(); p != nil {
		return p.List()
	}
	return DefaultRegistry.List()
}

// Reset clears the global Pipeline and DefaultRegistry state. It is
// intended for tests that need a clean slate between runs; production code
// should never call it.
func Reset() {
	globalPipeline.Store(nil)
	setupDone.Store(false)
	DefaultRegistry = NewRegistry()
}
