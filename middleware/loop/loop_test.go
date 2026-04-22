package loop

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/zlog/v2"
	"github.com/stretchr/testify/assert"
)

func Test_loop(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	middleware.Register("loop", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(&config.Config{})

	l := middleware.Get("loop").(*Loop)

	assert.Equal(t, "loop", l.Name())

	ch := middleware.NewChain([]middleware.Handler{l, l, l, l, l, l, l, l, l, l, l, l})

	ctx := context.Background()

	// Loop detection only engages on internal re-entries (the path
	// ExchangeInternal takes). Simulate that by using the internal
	// sentinel remote addr.
	mw := mock.NewWriter("tcp", "127.0.0.255:0")
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ch.Reset(mw, req)
	l.ServeDNS(ctx, ch)
	assert.Equal(t, dns.RcodeServerFailure, mw.Msg().Rcode)

	// External queries (non-internal writer) pass through without
	// engaging the tracker, so no SERVFAIL even when the same
	// handler fires many times.
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	l.ServeDNS(ctx, ch)
	assert.Nil(t, mw.Msg())

	// Empty-question requests are canceled outright.
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.Question = []dns.Question{}
	ch.Reset(mw, req)
	l.ServeDNS(ctx, ch)
	assert.Nil(t, mw.Msg())
}
