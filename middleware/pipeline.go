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
