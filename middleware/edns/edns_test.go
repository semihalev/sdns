package edns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_EDNS(t *testing.T) {
	testDomain := "example.com."

	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"

	blocklist := blocklist.New(cfg)
	blocklist.Set(testDomain)

	edns := New(cfg)
	assert.Equal(t, "edns", edns.Name())

	dc := ctx.New([]ctx.Handler{edns, blocklist})

	req := new(dns.Msg)
	req.SetQuestion(testDomain, dns.TypeA)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	dc.ResetDNS(mw, req)
	dc.NextDNS()

	assert.True(t, dc.DNSWriter.Written())
	assert.Equal(t, dns.RcodeSuccess, dc.DNSWriter.Rcode())
	assert.NotNil(t, dc.DNSWriter.Msg().IsEdns0())

	req.SetEdns0(4096, true)
	opt := req.IsEdns0()
	opt.SetVersion(100)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	dc.ResetDNS(mw, req)
	dc.NextDNS()

	assert.True(t, dc.DNSWriter.Written())
	assert.Equal(t, dns.RcodeBadVers, dc.DNSWriter.Rcode())
}
