package middleware

import (
	"errors"
	"sync"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
)

type middleware struct {
	mu sync.RWMutex

	cfg      *config.Config
	handlers []handler
}

type handler struct {
	name string
	new  func(*config.Config) ctx.Handler
}

var m middleware
var ctxHandlers []ctx.Handler
var alreadySetup bool

// Register a middleware
func Register(name string, new func(*config.Config) ctx.Handler) {
	log.Debug("Register middleware", "name", name)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler{name: name, new: new})
}

// SetConfig set config for handlers
func SetConfig(cfg *config.Config) {
	m.cfg = cfg
}

// Setup handlers
func Setup() error {
	if m.cfg == nil {
		return errors.New("set config first")
	}

	if alreadySetup {
		return errors.New("setup already done")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, handler := range m.handlers {
		ctxHandlers = append(ctxHandlers, handler.new(m.cfg))
	}

	alreadySetup = true

	return nil
}

// Handlers return registered handlers
func Handlers() []ctx.Handler {
	return ctxHandlers
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
func Get(name string) ctx.Handler {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for i, handler := range m.handlers {
		if handler.name == name {
			if len(ctxHandlers) <= i {
				return nil
			}
			return ctxHandlers[i]
		}
	}

	return nil
}
