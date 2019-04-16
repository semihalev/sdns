package middleware

import (
	"errors"
	"fmt"
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

var (
	ctxHandlers []ctx.Handler
	setup       bool
	m           middleware
)

// Register a middleware
func Register(name string, new func(*config.Config) ctx.Handler) {
	RegisterAt(name, new, len(m.handlers))
}

func RegisterAt(name string, new func(*config.Config) ctx.Handler, idx int) {
	log.Info("Register middleware", "name", name, "index", idx)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.handlers = append(m.handlers, handler{})
	copy(m.handlers[idx+1:], m.handlers[idx:])
	m.handlers[idx] = handler{name: name, new: new}
}

func RegisterBefore(name string, new func(*config.Config) ctx.Handler, before string) {
	log.Info("Register middleware", "name", name, "before", before)

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
func Setup(cfg *config.Config) error {
	if setup {
		return errors.New("setup already done")
	}

	m.cfg = cfg

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, handler := range m.handlers {
		ctxHandlers = append(ctxHandlers, handler.new(m.cfg))
	}

	setup = true

	return nil
}

// Handlers return registered handlers
func Handlers() []ctx.Handler {
	return append(ctxHandlers)
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
	if !setup {
		return nil
	}

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
