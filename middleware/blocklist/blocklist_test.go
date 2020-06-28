package blocklist

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_BlockList(t *testing.T) {
	testDomain := "test.com."

	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"

	middleware.Setup(cfg)

	blocklist := middleware.Get("blocklist").(*BlockList)

	assert.Equal(t, "blocklist", blocklist.Name())
	blocklist.Set(testDomain)

	ch := middleware.NewChain([]middleware.Handler{})

	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	ch.Request = req

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	blocklist.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)

	req.SetQuestion("test.com.", dns.TypeAAAA)
	ch.Request = req

	blocklist.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	req.SetQuestion("test2.com.", dns.TypeA)
	blocklist.ServeDNS(context.Background(), ch)
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
}
