package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_RateLimit(t *testing.T) {
	cfg := new(config.Config)
	cfg.ClientRateLimit = 1

	r := New(cfg)
	assert.Equal(t, "ratelimit", r.Name())

	dc := ctx.New([]ctx.Handler{})

	mw := mock.NewWriter("udp", "x")
	dc.DNSWriter = mw
	r.ServeDNS(dc)

	mw = mock.NewWriter("udp", "10.0.0.1")
	dc.DNSWriter = mw
	r.ServeDNS(dc)
	r.ServeDNS(dc)

	mw = mock.NewWriter("udp", "0.0.0.0")
	dc.DNSWriter = mw
	r.ServeDNS(dc)

	request, err := http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)
	request.RemoteAddr = "10.0.0.2:1"

	hw := httptest.NewRecorder()
	dc.ResetHTTP(hw, request)

	r.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

	r.ServeHTTP(dc)
	assert.Equal(t, 429, hw.Code)

	request, err = http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)

	hw = httptest.NewRecorder()
	dc.ResetHTTP(hw, request)

	r.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

	r.rate = 0

	r.ServeDNS(dc)

	request.RemoteAddr = "10.0.0.2:1"
	r.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

	r.now = func() time.Time {
		return time.Now().Add(expireTime)
	}

	r.clear()
	assert.Equal(t, 0, len(r.m))
}
