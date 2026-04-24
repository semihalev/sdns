package middleware

import (
	"context"
	"sync"
	"testing"

	"github.com/miekg/dns"
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
	assert.Nil(t, p.SubPipeline("x"))
	assert.Nil(t, p.NewChain())
	assert.Nil(t, p.Purgers())
}

// purgerHandler implements both Handler and Purger; used to verify
// Pipeline.Purgers enumerates only handlers implementing Purger.
type purgerHandler struct {
	n       string
	purgedQ []string
}

func (h *purgerHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *purgerHandler) Name() string                            { return h.n }
func (h *purgerHandler) Purge(q dns.Question)                    { h.purgedQ = append(h.purgedQ, q.Name) }

func Test_Pipeline_SubPipeline_FiltersByName(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("a", func(*config.Config) Handler { return &namedHandler{n: "a"} })
	Register("b", func(*config.Config) Handler { return &namedHandler{n: "b"} })
	Register("c", func(*config.Config) Handler { return &namedHandler{n: "c"} })

	Setup(&config.Config{})

	sub := GlobalPipeline().SubPipeline("b")
	assert.Equal(t, 2, len(sub.Handlers()))
	assert.Equal(t, "a", sub.Handlers()[0].Name())
	assert.Equal(t, "c", sub.Handlers()[1].Name())
	assert.Nil(t, sub.Get("b"), "filtered handler must not be reachable via Get")

	// Skipping a name that isn't in the pipeline is a no-op.
	sub2 := GlobalPipeline().SubPipeline("nope")
	assert.Equal(t, 3, len(sub2.Handlers()))
}

func Test_Pipeline_NewChain_IsFreshPerCall(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("a", func(*config.Config) Handler { return &namedHandler{n: "a"} })
	Setup(&config.Config{})

	p := GlobalPipeline()
	c1 := p.NewChain()
	c2 := p.NewChain()
	assert.NotNil(t, c1)
	assert.NotNil(t, c2)
	assert.NotSame(t, c1, c2, "each NewChain call must return a distinct instance")
}

func Test_Pipeline_Purgers_EnumeratesOnlyPurgerHandlers(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	p1 := &purgerHandler{n: "cache"}
	p2 := &purgerHandler{n: "resolver"}
	Register("cache", func(*config.Config) Handler { return p1 })
	Register("plain", func(*config.Config) Handler { return &namedHandler{n: "plain"} })
	Register("resolver", func(*config.Config) Handler { return p2 })

	Setup(&config.Config{})

	pp := GlobalPipeline().Purgers()
	assert.Equal(t, 2, len(pp), "non-Purger handlers must be excluded")

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for _, pr := range pp {
		pr.Purge(q)
	}
	assert.Equal(t, []string{"example.com."}, p1.purgedQ)
	assert.Equal(t, []string{"example.com."}, p2.purgedQ)
}
