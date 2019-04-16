package middleware

import (
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(dc *ctx.Context) { dc.NextDNS() }
func (d *dummy) Name() string             { return "dummy" }

func Test_Middleware(t *testing.T) {
	Register("dummy", func(*config.Config) ctx.Handler {
		return &dummy{}
	})

	cfg := &config.Config{}

	d := Get("dummy")
	assert.Nil(t, d)

	err := Setup(cfg)
	assert.NoError(t, err)

	err = Setup(cfg)
	assert.Error(t, err)

	assert.True(t, len(List()) == 1)
	assert.True(t, len(Handlers()) == 1)

	d = Get("dummy")
	assert.NotNil(t, d)

	d = Get("none")
	assert.Nil(t, d)

	ctxHandlers = []ctx.Handler{}
	d = Get("dummy")
	assert.Nil(t, d)
}

func Test_RegisterAt(t *testing.T) {
	m.handlers = []handler{}

	Register("dummy", func(*config.Config) ctx.Handler {
		return &dummy{}
	})
	RegisterAt("dummy2", func(*config.Config) ctx.Handler {
		return &dummy{}
	}, 0)

	assert.True(t, len(m.handlers) == 2)
	assert.True(t, m.handlers[0].name == "dummy2")
	assert.True(t, m.handlers[1].name == "dummy")

	RegisterBefore("dummy3", func(*config.Config) ctx.Handler {
		return &dummy{}
	}, "dummy")
	assert.True(t, len(m.handlers) == 3)
	assert.True(t, m.handlers[0].name == "dummy2")
	assert.True(t, m.handlers[0].name == "dummy2")
	assert.True(t, m.handlers[1].name == "dummy3")
	assert.True(t, m.handlers[2].name == "dummy")

	assert.Panics(t, func() {
		RegisterAt("dummy4", func(*config.Config) ctx.Handler {
			return &dummy{}
		}, 4)
	})
	assert.Panics(t, func() {
		RegisterAt("dummy5", func(*config.Config) ctx.Handler {
			return &dummy{}
		}, -1)
	})
	assert.Panics(t, func() {
		RegisterBefore("dummy6", func(*config.Config) ctx.Handler {
			return &dummy{}
		}, "noexist")
	})

	m.handlers = []handler{}
}
