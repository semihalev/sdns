package forwarder

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Forwarder(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	cfg := new(config.Config)
	cfg.ForwarderServers = []string{"[::255]:53", "8.8.8.8:53", "1", "tls://8.8.8.8:853"}

	middleware.Register("forwarder", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	f := middleware.Get("forwarder").(*Forwarder)
	assert.Equal(t, "forwarder", f.Name())

	ch := middleware.NewChain([]middleware.Handler{f})

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	ch.Request = req

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	req.RecursionDesired = true

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)

	f.servers = []*server{}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)

	srv := &server{Addr: "[::255]:53", Proto: "udp"}
	f.servers = []*server{srv}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)

	srv = &server{Addr: "8.8.8.8:853", Proto: "tcp-tls"}
	f.servers = []*server{srv}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)
}
