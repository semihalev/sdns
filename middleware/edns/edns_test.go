package edns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	m := new(dns.Msg)
	m.SetReply(req)

	rrHeader := dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	a := &dns.A{Hdr: rrHeader, A: net.ParseIP("127.0.0.1")}

	for i := 0; i < 100; i++ {
		m.Answer = append(m.Answer, a)
	}

	w.WriteMsg(m)
}

func (d *dummy) Name() string { return "dummy" }

func Test_EDNS(t *testing.T) {
	testDomain := "example.com."

	cfg := new(config.Config)
	middleware.Setup(cfg)

	edns := middleware.Get("edns").(*EDNS)
	assert.Equal(t, "edns", edns.Name())

	dc := ctx.New([]ctx.Handler{edns, &dummy{}})

	req := new(dns.Msg)
	req.SetQuestion(testDomain, dns.TypeA)

	mw := mock.NewWriter("tcp", "127.0.0.1:0")
	dc.ResetDNS(mw, req)
	dc.NextDNS()

	assert.True(t, dc.DNSWriter.Written())
	assert.Equal(t, dns.RcodeSuccess, dc.DNSWriter.Rcode())
	assert.Nil(t, dc.DNSWriter.Msg().IsEdns0())

	req.SetEdns0(4096, true)
	opt := req.IsEdns0()
	opt.SetVersion(100)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	dc.ResetDNS(mw, req)
	dc.NextDNS()

	assert.True(t, dc.DNSWriter.Written())
	assert.Equal(t, dns.RcodeBadVers, dc.DNSWriter.Rcode())

	opt = req.IsEdns0()
	opt.SetVersion(0)
	opt.SetUDPSize(512)

	mw = mock.NewWriter("tcp", "127.0.0.1:0")
	dc.ResetDNS(mw, req)
	dc.NextDNS()

	if assert.True(t, dc.DNSWriter.Written()) {
		assert.False(t, dc.DNSWriter.Msg().Truncated)
	}

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	dc.ResetDNS(mw, req)
	dc.NextDNS()

	if assert.True(t, dc.DNSWriter.Written()) {
		assert.True(t, dc.DNSWriter.Msg().Truncated)
	}

	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "testtesttesttest",
	})
	opt.SetUDPSize(4096)
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	dc.ResetDNS(mw, req)
	dc.NextDNS()
}
