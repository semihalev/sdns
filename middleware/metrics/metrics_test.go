package metrics

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Metrics(t *testing.T) {
	middleware.Setup(&config.Config{})

	m := middleware.Get("metrics").(*Metrics)

	assert.Equal(t, "metrics", m.Name())

	ch := middleware.NewChain([]middleware.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	ch.Reset(mw, req)

	m.ServeDNS(context.Background(), ch)
	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	_ = ch.Writer.WriteMsg(req)
	assert.Equal(t, true, ch.Writer.Written())

	m.ServeDNS(context.Background(), ch)
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())
}
