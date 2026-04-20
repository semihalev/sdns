package middleware

import (
	"context"
	"sync"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (d *dummy) Name() string                            { return "dummy" }

type namedHandler struct{ n string }

func (h *namedHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *namedHandler) Name() string                            { return h.n }

func Test_DefaultRegistry_Setup(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("dummy", func(*config.Config) Handler { return &dummy{} })

	assert.Nil(t, Get("dummy"), "Get before Setup must return nil")
	assert.False(t, Ready())

	Setup(&config.Config{})

	assert.True(t, Ready())
	assert.Panics(t, func() { Setup(&config.Config{}) }, "double Setup must panic")

	assert.Equal(t, []string{"dummy"}, List())
	assert.Equal(t, 1, len(Handlers()))

	d := Get("dummy")
	if assert.NotNil(t, d) {
		assert.Equal(t, "dummy", d.Name())
	}
	assert.Nil(t, Get("none"))
}

// Test_Get_SkipsDisabled guards against a regression where disabled
// middlewares shifted the Get() index lookup onto the next enabled handler.
func Test_Get_SkipsDisabled(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("first", func(*config.Config) Handler { return &namedHandler{n: "first"} })
	Register("disabled", func(*config.Config) Handler {
		var h *namedHandler // typed-nil => isNilHandler skips it
		return h
	})
	Register("second", func(*config.Config) Handler { return &namedHandler{n: "second"} })

	Setup(&config.Config{})

	assert.Equal(t, 2, len(Handlers()))
	assert.Equal(t, []string{"first", "disabled", "second"}, List())

	if h := Get("first"); assert.NotNil(t, h) {
		assert.Equal(t, "first", h.Name())
	}
	assert.Nil(t, Get("disabled"))
	if h := Get("second"); assert.NotNil(t, h) {
		assert.Equal(t, "second", h.Name())
	}
}

func Test_Registry_RegisterAt(t *testing.T) {
	r := NewRegistry()

	r.Register("dummy", func(*config.Config) Handler { return &dummy{} })
	r.RegisterAt("dummy2", func(*config.Config) Handler { return &dummy{} }, 0)
	r.RegisterBefore("dummy3", func(*config.Config) Handler { return &dummy{} }, "dummy")

	assert.Equal(t, []string{"dummy2", "dummy3", "dummy"}, r.List())

	assert.Panics(t, func() {
		r.RegisterAt("tooHigh", func(*config.Config) Handler { return &dummy{} }, 99)
	})
	assert.Panics(t, func() {
		r.RegisterAt("tooLow", func(*config.Config) Handler { return &dummy{} }, -1)
	})
	assert.Panics(t, func() {
		r.RegisterBefore("orphan", func(*config.Config) Handler { return &dummy{} }, "nope")
	})
	assert.Panics(t, func() {
		r.Register("dummy", func(*config.Config) Handler { return &dummy{} })
	}, "duplicate Register must panic")
}

func Test_Registry_Build_ConcurrentReads(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("h", func(*config.Config) Handler { return &namedHandler{n: "h"} })
	Setup(&config.Config{})

	var wg sync.WaitGroup
	const readers = 16
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			for range 1000 {
				_ = Handlers()
				_ = Get("h")
				_ = Ready()
			}
		}()
	}
	wg.Wait()
}

func Test_Pipeline_NilSafe(t *testing.T) {
	var p *Pipeline
	assert.Nil(t, p.Handlers())
	assert.Nil(t, p.Get("anything"))
	assert.Nil(t, p.List())
}
