package accesslist

import (
	"context"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/zlog"
	"github.com/stretchr/testify/assert"
)

func Test_AccesslistDefaults(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	cfg.AccessList = []string{}

	a := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{a})

	mw := mock.NewWriter("udp", "8.8.8.8:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
}

func Test_Accesslist(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	cfg.AccessList = []string{"127.0.0.1/32", "1"}

	middleware.Register("accesslist", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	a := middleware.Get("accesslist").(*AccessList)
	assert.Equal(t, "accesslist", a.Name())

	ch := middleware.NewChain([]middleware.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.255:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)

	mw = mock.NewWriter("udp", "0.0.0.0:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
}
