package chaos

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Chaos(t *testing.T) {
	cfg := new(config.Config)
	cfg.Chaos = true

	middleware.Setup(cfg)

	c := middleware.Get("chaos").(*Chaos)
	assert.Equal(t, "chaos", c.Name())

	ch := middleware.NewChain([]middleware.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("version.bind.", dns.TypeTXT)
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)

	assert.False(t, mw.Written())

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.Question[0].Qclass = dns.ClassCHAOS
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)

	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.Question[0].Name = "hostname.bind."
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)

	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.Question[0].Name = "unknown.bind."
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)

	assert.False(t, mw.Written())
}
