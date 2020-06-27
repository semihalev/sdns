package metrics

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Metrics(t *testing.T) {
	middleware.Setup(&config.Config{})

	m := middleware.Get("metrics").(*Metrics)

	assert.Equal(t, "metrics", m.Name())

	dc := ctx.New([]ctx.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	dc.Reset(mw, req)

	m.ServeDNS(context.Background(), dc)
	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	dc.DNSWriter.WriteMsg(req)
	assert.Equal(t, true, dc.DNSWriter.Written())

	m.ServeDNS(context.Background(), dc)
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())
}
