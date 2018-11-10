package accesslist

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Accesslist(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	cfg := new(config.Config)
	cfg.AccessList = []string{"127.0.0.1/32", "1"}

	a := New(cfg)
	assert.Equal(t, "accesslist", a.Name())

	dc := ctx.New([]ctx.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1")
	dc.DNSWriter = mw
	a.ServeDNS(dc)

	mw = mock.NewWriter("udp", "0.0.0.0")
	dc.DNSWriter = mw
	a.ServeDNS(dc)

	request, err := http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)
	request.RemoteAddr = "127.0.0.1:0"

	hw := httptest.NewRecorder()
	dc.ResetHTTP(hw, request)

	a.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

	request, err = http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)

	hw = httptest.NewRecorder()
	dc.ResetHTTP(hw, request)

	a.ServeHTTP(dc)
	assert.Equal(t, 401, hw.Code)
}
