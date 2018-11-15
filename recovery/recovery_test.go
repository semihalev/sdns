package recovery

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_recoveryDNS(t *testing.T) {
	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)

	r := &Recovery{}

	dc := ctx.New([]ctx.Handler{r, nil})

	mw := mock.NewWriter("udp", "127.0.0.1")
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

func Test_recoveryHTTP(t *testing.T) {
	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)

	r := &Recovery{}

	dc := ctx.New([]ctx.Handler{r, nil})

	request, err := http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)
	request.RemoteAddr = "127.0.0.1:0"

	hw := httptest.NewRecorder()
	dc.ResetHTTP(hw, request)

	r.ServeHTTP(dc)
	assert.Equal(t, 500, hw.Code)

	dc = ctx.New([]ctx.Handler{r})
	dc.ResetHTTP(hw, request)
	r.ServeHTTP(dc)

	os.Stderr = stderr
}
