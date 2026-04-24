package middleware

import (
	"fmt"
	"maps"
	"plugin"
	"sync"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/zlog/v2"
)

// Registry collects middleware registrations and builds an immutable
// Pipeline from them. A Registry is safe for concurrent Register calls,
// but Build is expected to be called once.
type Registry struct {
	mu       sync.Mutex
	order    []string
	builders map[string]Constructor
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{builders: make(map[string]Constructor)}
}

// Register appends a middleware to the end of the registry.
func (r *Registry) Register(name string, c Constructor) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.insertAt(name, c, len(r.order))
	zlog.Debug("Register middleware", "name", name, "index", len(r.order)-1)
}

// RegisterAt inserts a middleware at the given index. Out-of-range index
// panics.
func (r *Registry) RegisterAt(name string, c Constructor, idx int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if idx < 0 || idx > len(r.order) {
		panic(fmt.Sprintf("middleware: RegisterAt index %d out of range [0,%d]", idx, len(r.order)))
	}
	r.insertAt(name, c, idx)
	zlog.Debug("Register middleware", "name", name, "index", idx)
}

// RegisterBefore inserts a middleware immediately before the named one.
// Panics if `before` is not registered.
func (r *Registry) RegisterBefore(name string, c Constructor, before string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for idx, n := range r.order {
		if n == before {
			r.insertAt(name, c, idx)
			zlog.Debug("Register middleware", "name", name, "before", before)
			return
		}
	}
	panic(fmt.Sprintf("middleware: RegisterBefore target %q not found", before))
}

// insertAt is the shared shift-and-insert core. Caller must hold r.mu.
func (r *Registry) insertAt(name string, c Constructor, idx int) {
	if _, dup := r.builders[name]; dup {
		panic(fmt.Sprintf("middleware: %q already registered", name))
	}
	r.order = append(r.order, "")
	copy(r.order[idx+1:], r.order[idx:])
	r.order[idx] = name
	r.builders[name] = c
}

// List returns the registered middleware names in order.
func (r *Registry) List() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// Build runs every Constructor against cfg, skips disabled middlewares
// (typed-nil), and returns an immutable Pipeline. Constructors run outside
// the registry lock, so they may do heavy work (open files, spawn
// goroutines) without starving concurrent List calls.
func (r *Registry) Build(cfg *config.Config) *Pipeline {
	r.mu.Lock()
	order := make([]string, len(r.order))
	copy(order, r.order)
	builders := make(map[string]Constructor, len(r.builders))
	maps.Copy(builders, r.builders)
	r.mu.Unlock()

	handlers := make([]Handler, 0, len(order))
	byName := make(map[string]Handler, len(order))
	for i, name := range order {
		h := builders[name](cfg)
		if isNilHandler(h) {
			zlog.Debug("Middleware not enabled", "name", name, "index", i)
			continue
		}
		handlers = append(handlers, h)
		byName[h.Name()] = h
		zlog.Debug("Middleware registered", "name", h.Name(), "index", i)
	}

	return newPipeline(handlers, byName, order)
}

// loadPlugins walks cfg.Plugins, opens each as a Go plugin and registers
// its New function via RegisterBefore("cache"). This preserves the legacy
// placement of dynamic plugins ahead of the cache.
func (r *Registry) loadPlugins(cfg *config.Config) {
	for name, pcfg := range cfg.Plugins {
		pl, err := plugin.Open(pcfg.Path)
		if err != nil {
			zlog.Error("Plugin open failed", "plugin", name, "error", err.Error())
			continue
		}

		sym, err := pl.Lookup("New")
		if err != nil {
			zlog.Error("Plugin New lookup failed", "plugin", name, "error", err.Error())
			continue
		}

		newFn, ok := sym.(func(cfg *config.Config) Handler)
		if !ok {
			zlog.Error("Plugin New has wrong signature", "plugin", name)
			continue
		}

		r.RegisterBefore(name, Constructor(newFn), "cache")
		zlog.Info("Plugin loaded", "plugin", name, "path", pcfg.Path)
	}
}

// DefaultRegistry is the package-level registry used by the top-level
// Register / RegisterAt / RegisterBefore wrappers. Middleware packages
// register into it from their init hooks.
var DefaultRegistry = NewRegistry()

// Register is a package-level shortcut for DefaultRegistry.Register.
func Register(name string, c Constructor) {
	DefaultRegistry.Register(name, c)
}

// RegisterAt is a package-level shortcut for DefaultRegistry.RegisterAt.
func RegisterAt(name string, c Constructor, idx int) {
	DefaultRegistry.RegisterAt(name, c, idx)
}

// RegisterBefore is a package-level shortcut for
// DefaultRegistry.RegisterBefore.
func RegisterBefore(name string, c Constructor, before string) {
	DefaultRegistry.RegisterBefore(name, c, before)
}
