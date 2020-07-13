package middleware

import (
	"context"
	"fmt"
	"plugin"
	"sync"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
)

// Handler interface
type Handler interface {
	Name() string
	ServeDNS(context.Context, *Chain)
}

type middleware struct {
	mu sync.RWMutex

	cfg      *config.Config
	handlers []handler
}

type handler struct {
	name string
	new  func(*config.Config) Handler
}

var (
	chainHandlers []Handler
	setup         bool
	m             middleware
)

// Register a middleware
func Register(name string, new func(*config.Config) Handler) {
	RegisterAt(name, new, len(m.handlers))
}

// RegisterAt a middleware at an index
func RegisterAt(name string, new func(*config.Config) Handler, idx int) {
	log.Debug("Register middleware", "name", name, "index", idx)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.handlers = append(m.handlers, handler{})
	copy(m.handlers[idx+1:], m.handlers[idx:])
	m.handlers[idx] = handler{name: name, new: new}
}

// RegisterBefore a middleware before another middleware
func RegisterBefore(name string, new func(*config.Config) Handler, before string) {
	log.Debug("Register middleware", "name", name, "before", before)

	m.mu.Lock()
	defer m.mu.Unlock()

	for idx, v := range m.handlers {
		if v.name == before {
			m.handlers = append(m.handlers, handler{})
			copy(m.handlers[idx+1:], m.handlers[idx:])
			m.handlers[idx] = handler{name: name, new: new}
			return
		}
	}

	panic(fmt.Sprintf("Middleware %s not found", before))
}

// Setup handlers
func Setup(cfg *config.Config) {
	if setup {
		panic("middleware setup already done")
	}

	m.cfg = cfg

	LoadExternalPlugins()

	m.mu.Lock()
	defer m.mu.Unlock()

	for i, handler := range m.handlers {
		h := handler.new(m.cfg)
		chainHandlers = append(chainHandlers, h)

		log.Debug("Middleware registered", "name", h.Name(), "index", i)
	}

	setup = true
}

// LoadExternalPlugins load external plugins into chain
func LoadExternalPlugins() {
	for name, pcfg := range m.cfg.Plugins {
		pl, err := plugin.Open(pcfg.Path)
		if err != nil {
			log.Error("Plugin open failed", "plugin", name, "error", err.Error())
			continue
		}

		newFuncSym, err := pl.Lookup("New")
		if err != nil {
			log.Error("Plugin new function lookup failed", "plugin", name, "error", err.Error())
			continue
		}

		newFn, ok := newFuncSym.(func(cfg *config.Config) Handler)

		if !ok {
			log.Error("Plugin new function assert failed", "plugin", name)
			continue
		}

		RegisterBefore(name, newFn, "cache")
		log.Info("Plugin successfully loaded", "plugin", name, "path", pcfg.Path)
	}
}

// Handlers return registered handlers
func Handlers() []Handler {
	handlers := chainHandlers
	return handlers
}

// List return names of handlers
func List() (list []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, handler := range m.handlers {
		list = append(list, handler.name)
	}

	return list
}

// Get return a handler by name
func Get(name string) Handler {
	if !setup {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for i, handler := range m.handlers {
		if handler.name == name {
			if len(chainHandlers) <= i {
				return nil
			}
			return chainHandlers[i]
		}
	}

	return nil
}

// Ready return true if middleware setup was done
func Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return setup
}
