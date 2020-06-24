package failover

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	w.WriteMsg(dnsutil.HandleFailed(req, dns.RcodeServerFailure, true))
}

func (d *dummy) Name() string { return "dummy" }

func Test_Failover(t *testing.T) {
	cfg := new(config.Config)
	cfg.FallbackServers = []string{"[::255]:53", "1.1.1.1:53", "1"}

	middleware.Setup(cfg)

	f := middleware.Get("failover").(*Failover)
	assert.Equal(t, "failover", f.Name())

	dc := ctx.New([]ctx.Handler{f, &dummy{}})

	ctxb := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	dc.DNSWriter = mw
	dc.DNSRequest = req

	dc.ResetDNS(mw, req)
	dc.NextDNS(ctxb)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)

	req.RecursionDesired = true

	dc.ResetDNS(mw, req)
	dc.NextDNS(ctxb)

	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)

	f.servers = []string{}

	dc.ResetDNS(mw, req)
	dc.NextDNS(ctxb)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)

	f.servers = []string{"[::255]:53"}

	dc.ResetDNS(mw, req)
	dc.NextDNS(ctxb)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)
}
