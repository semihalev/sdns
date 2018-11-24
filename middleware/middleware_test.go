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
