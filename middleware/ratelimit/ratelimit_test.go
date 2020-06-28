package ratelimit

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_RateLimit(t *testing.T) {
	cfg := new(config.Config)
	cfg.ClientRateLimit = 1

	middleware.Setup(cfg)

	r := middleware.Get("ratelimit").(*RateLimit)

	assert.Equal(t, "ratelimit", r.Name())

	ch := middleware.NewChain([]middleware.Handler{})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, true)

	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "testtesttesttest",
	})

	mw := mock.NewWriter("udp", "")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	mw = mock.NewWriter("udp", "10.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	r.ServeDNS(context.Background(), ch)
	if assert.True(t, mw.Written()) {
		assert.Equal(t, dns.RcodeBadCookie, mw.Rcode())
	}

	opt.Option = nil
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "testtesttesttest",
	})

	mw = mock.NewWriter("udp", "10.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	assert.False(t, mw.Written())

	mw = mock.NewWriter("tcp", "10.0.0.2:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	r.ServeDNS(context.Background(), ch)
	assert.False(t, mw.Written())

	opt.Option = nil
	mw = mock.NewWriter("udp", "10.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)
	r.ServeDNS(context.Background(), ch)
	assert.False(t, mw.Written())

	mw = mock.NewWriter("udp", "0.0.0.0:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	r.rate = 0

	r.ServeDNS(context.Background(), ch)
}
