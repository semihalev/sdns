package as112

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_AS112(t *testing.T) {
	cfg := new(config.Config)
	cfg.EmptyZones = []string{
		"10.in-addr.arpa.",
		"example.arpa",
	}

	middleware.Setup(cfg)

	a := middleware.Get("as112").(*AS112)

	assert.Equal(t, "as112", a.Name())

	ch := middleware.NewChain([]middleware.Handler{})

	req := new(dns.Msg)
	req.SetQuestion("10.in-addr.arpa.", dns.TypeSOA)
	ch.Request = req

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	a.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	req.SetQuestion("10.in-addr.arpa.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	req.SetQuestion("10.in-addr.arpa.", dns.TypeSOA)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	req.SetQuestion("10.in-addr.arpa.", dns.TypeDS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.False(t, mw.Written())

	req.SetQuestion("20.in-addr.arpa.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.False(t, mw.Written())

	req.SetQuestion("example.com.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.False(t, mw.Written())

	req.SetQuestion("10.10.in-addr.arpa.", dns.TypeSOA)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Ns) > 0)
	assert.Equal(t, dns.RcodeNameError, mw.Rcode())

	req.SetQuestion("10.10.in-addr.arpa.", dns.TypeA)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Ns) > 0)
	assert.Equal(t, dns.RcodeNameError, mw.Rcode())

	req.SetQuestion("10.10.in-addr.arpa.", dns.TypeNS)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	a.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Ns) > 0)
	assert.Equal(t, dns.RcodeNameError, mw.Rcode())
}
