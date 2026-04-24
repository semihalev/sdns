package middleware

import (
	"sync"
	"sync/atomic"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/util"
)

// Pipeline is the compiled, immutable middleware chain produced by
// Registry.Build. Handler fields are set at construction time and
// never mutated, so every read is safe without synchronization.
// chainPool is internally mutable (sync.Pool's contract) but serves
// the same Pipeline across all callers — pooling *Chain is the
// per-internal-query alloc-saver that the pre-retirement
// util.ExchangeInternal provided.
type Pipeline struct {
	handlers  []Handler
	byName    map[string]Handler
	names     []string // full registered name list, including disabled
	chainPool sync.Pool
}

// newPipeline constructs a Pipeline and initialises its chain pool.
// Used by Registry.Build and Pipeline.SubPipeline so every pipeline
// (full and sub) gets its own pool bound to its own handler list.
func newPipeline(handlers []Handler, byName map[string]Handler, names []string) *Pipeline {
	p := &Pipeline{handlers: handlers, byName: byName, names: names}
	p.chainPool.New = func() any {
		return NewChain(p.handlers)
	}
	return p
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
	return newPipeline(handlers, byName, p.names)
}

// NewChain returns a Chain bound to this pipeline's handlers,
// pulled from the pipeline's own sync.Pool. Callers that dispatch
// internal sub-queries (queryer.Queryer) should return the chain
// via PutChain after use to keep per-sub-query allocations off the
// hot path. Callers that build a chain for long-lived use don't
// need to return it.
func (p *Pipeline) NewChain() *Chain {
	if p == nil {
		return nil
	}
	return p.chainPool.Get().(*Chain)
}

// PutChain returns ch to the pipeline's pool. Safe to call with a
// chain from any pipeline — the sync.Pool is per-pipeline so cross
// put/get only causes a pool mismatch (never a correctness bug),
// but callers should pair PutChain with NewChain from the same
// Pipeline to keep the pool warm.
func (p *Pipeline) PutChain(ch *Chain) {
	if p == nil || ch == nil {
		return
	}
	p.chainPool.Put(ch)
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
// publishes the resulting Pipeline globally, and auto-wires
// sub-pipeline Queryers and shared Stores into every handler that
// implements the corresponding *Setter interface. It panics if
// called more than once without an intervening Reset.
//
// Wiring sequence (after Build):
//  1. Build queryerSub by filtering handlers that report
//     ClientOnly()==true.
//  2. Build prefetchSub as queryerSub without the cache handler
//     (named "cache") — prefetch must reach the upstream resolver
//     / forwarder instead of returning its own about-to-expire
//     entry.
//  3. Construct a PipelineQueryer for each sub-pipeline.
//  4. Walk enabled handlers and call SetQueryer / SetPrefetchQueryer
//     / SetStore on anything that implements them, sourcing the
//     Store from whichever handler implements StoreProvider.
//
// This keeps the main package free of wiring logic — every
// middleware declares its participation in the internal chain
// (ClientOnly), and every consumer declares what it needs
// (QueryerSetter, StoreSetter, etc.).
func Setup(cfg *config.Config) {
	if !setupDone.CompareAndSwap(false, true) {
		panic("middleware: Setup already called")
	}
	DefaultRegistry.loadPlugins(cfg)
	p := DefaultRegistry.Build(cfg)
	// Auto-wire BEFORE publishing the pipeline. The resolver's
	// background priming goroutine spins on middleware.Ready() and
	// starts issuing sub-queries the instant it returns true; if
	// we published before wiring, the goroutine would race the
	// queryer/store field writes here. Publishing after wiring
	// means the atomic.Pointer.Store also acts as a happens-before
	// barrier for every field the goroutine subsequently reads.
	p.autoWire()
	globalPipeline.Store(p)
}

// cacheHandlerName is the registered name of the cache middleware,
// special-cased in prefetchSub construction — prefetch must refresh
// the upstream, not return its own entry.
const cacheHandlerName = "cache"

// autoWire builds queryerSub and prefetchSub from the current
// pipeline, then injects them into every handler that implements
// the corresponding *Setter interface. Stores are sourced from
// whichever handler implements StoreProvider.
func (p *Pipeline) autoWire() {
	if p == nil {
		return
	}

	skip := make([]string, 0, len(p.handlers))
	for _, h := range p.handlers {
		if co, ok := h.(ClientOnly); ok && co.ClientOnly() {
			skip = append(skip, h.Name())
		}
	}
	queryerSub := p.SubPipeline(skip...)
	prefetchSub := p.SubPipeline(append(skip, cacheHandlerName)...)

	q := NewPipelineQueryer(queryerSub)
	pq := NewPipelineQueryer(prefetchSub)

	var store Store
	for _, h := range p.handlers {
		if sp, ok := h.(StoreProvider); ok {
			store = sp.Store()
			break
		}
	}

	for _, h := range p.handlers {
		if s, ok := h.(QueryerSetter); ok {
			s.SetQueryer(q)
		}
		if s, ok := h.(PrefetchQueryerSetter); ok {
			s.SetPrefetchQueryer(pq)
		}
		if store != nil {
			if s, ok := h.(StoreSetter); ok {
				s.SetStore(store)
			}
		}
	}

	// Back the deprecated util.ExchangeInternal with the same
	// queryer. Plugins that still call the old API transparently
	// pick up the sub-pipeline semantics; the wrapper is flagged
	// for next-major removal.
	util.SetInternalExchanger(q.Query)
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
