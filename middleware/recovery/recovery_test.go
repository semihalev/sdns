package recovery

import (
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_recoveryDNS(t *testing.T) {
	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)

	middleware.Setup(nil)
	r := middleware.Get("recovery").(*Recovery)

	dc := ctx.New([]ctx.Handler{r, nil})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	dc.ResetDNS(mw, req)

	assert.Equal(t, "recovery", r.Name())

	r.ServeDNS(dc)

	assert.Equal(t, dns.RcodeServerFailure, mw.Msg().Rcode)

	dc = ctx.New([]ctx.Handler{r})
	dc.ResetDNS(mw, req)
	r.ServeDNS(dc)

	os.Stderr = stderr
}
