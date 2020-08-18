package failover

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)

	_ = w.WriteMsg(m)
}

func (d *dummy) Name() string { return "dummy" }

func Test_Failover(t *testing.T) {
	cfg := new(config.Config)
	cfg.FallbackServers = []string{"[::255]:53", "1.1.1.1:53", "1"}

	middleware.Setup(cfg)

	f := middleware.Get("failover").(*Failover)
	assert.Equal(t, "failover", f.Name())

	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	ch.Request = req

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	req.RecursionDesired = true

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)

	f.servers = []string{}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)

	f.servers = []string{"[::255]:53"}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)
}
