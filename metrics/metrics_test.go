package metrics

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Metrics(t *testing.T) {
	m := New(nil)

	assert.Equal(t, "metrics", m.Name())

	dc := ctx.New([]ctx.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	dc.ResetDNS(mw, req)

	m.ServeDNS(dc)
	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	dc.DNSWriter.WriteMsg(req)
	assert.Equal(t, true, dc.DNSWriter.Written())

	m.ServeDNS(dc)
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	m.ServeHTTP(dc)
}
