package blocklist

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/mock"

	"github.com/stretchr/testify/assert"
)

func Test_BlockList(t *testing.T) {
	testDomain := "test.com."

	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"

	blocklist := New(cfg)
	assert.Equal(t, "blocklist", blocklist.Name())
	blocklist.Set(testDomain)

	dc := ctx.New([]ctx.Handler{})

	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	dc.DNSRequest = req

	mw := mock.NewWriter("udp", "127.0.0.1")
	dc.DNSWriter = mw

	blocklist.ServeDNS(dc)
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)

	req.SetQuestion("test.com.", dns.TypeAAAA)
	dc.DNSRequest = req

	blocklist.ServeDNS(dc)
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)

	mw = mock.NewWriter("udp", "127.0.0.1")
	dc.DNSWriter = mw
	req.SetQuestion("test2.com.", dns.TypeA)
	blocklist.ServeDNS(dc)
	assert.Nil(t, mw.Msg())

	assert.Equal(t, blocklist.Exists(testDomain), true)
	assert.Equal(t, blocklist.Exists(strings.ToUpper(testDomain)), true)

	_, err := blocklist.Get(testDomain)
	assert.NoError(t, err)

	assert.Equal(t, blocklist.Length(), 1)

	if exists := blocklist.Exists(fmt.Sprintf("%sfuzz", testDomain)); exists {
		t.Error("fuzz existed in block blocklist")
	}

	if blocklistLen := blocklist.Length(); blocklistLen != 1 {
		t.Error("invalid length: ", blocklistLen)
	}

	blocklist.Remove(testDomain)
	assert.Equal(t, blocklist.Exists(testDomain), false)

	_, err = blocklist.Get(testDomain)
	assert.Error(t, err)

	blocklist.Set(testDomain)

	request, err := http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)

	hw := httptest.NewRecorder()
	dc.ResetHTTP(hw, request)
	blocklist.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

	request, err = http.NewRequest("GET", "/dns-query?name=notest.com", nil)
	assert.NoError(t, err)

	hw = httptest.NewRecorder()
	dc.ResetHTTP(hw, request)
	blocklist.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

	data, err := req.Pack()
	assert.NoError(t, err)

	dq := base64.RawURLEncoding.EncodeToString(data)

	request, err = http.NewRequest("GET", fmt.Sprintf("/dns-query?dns=%s", dq), nil)
	assert.NoError(t, err)

	hw = httptest.NewRecorder()
	dc.ResetHTTP(hw, request)
	blocklist.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)
}
