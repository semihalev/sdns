package blocklist

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp")

	middleware.Register("blocklist", func(cfg *config.Config) middleware.Handler { return New(cfg) })
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

	req.SetQuestion("test.com.", dns.TypeNS)
	ch.Request = req

	blocklist.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, len(mw.Msg().Ns) > 0)

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

func Test_BlockList_Wildcard(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_wildcard")

	blocklist := New(cfg)

	// Test wildcard blocking
	blocklist.Set("*.blocked.com.")

	// These should all be blocked
	assert.True(t, blocklist.Exists("subdomain.blocked.com."))
	assert.True(t, blocklist.Exists("deep.subdomain.blocked.com."))
	assert.True(t, blocklist.Exists("very.deep.subdomain.blocked.com."))

	// The base domain should not be blocked (only subdomains)
	assert.False(t, blocklist.Exists("blocked.com."))

	// Other domains should not be blocked
	assert.False(t, blocklist.Exists("notblocked.com."))
	assert.False(t, blocklist.Exists("subdomain.notblocked.com."))

	// Test exact domain blocking
	blocklist.Set("exact.com.")
	assert.True(t, blocklist.Exists("exact.com."))
	assert.False(t, blocklist.Exists("subdomain.exact.com."))

	// Test multiple wildcard levels
	blocklist.Set("*.subdomain.multi.com.")
	assert.True(t, blocklist.Exists("test.subdomain.multi.com."))
	assert.True(t, blocklist.Exists("deep.test.subdomain.multi.com."))
	assert.False(t, blocklist.Exists("subdomain.multi.com."))
	assert.False(t, blocklist.Exists("multi.com."))

	// Test with ServeDNS
	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.blocked.com.", dns.TypeA)
	ch.Request = req

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	blocklist.ServeDNS(context.Background(), ch)
	assert.NotNil(t, mw.Msg())
	assert.Equal(t, true, len(mw.Msg().Answer) > 0)

	// Test non-blocked domain
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	req.SetQuestion("allowed.com.", dns.TypeA)
	blocklist.ServeDNS(context.Background(), ch)
	assert.Nil(t, mw.Msg())

	// Test case insensitivity
	assert.True(t, blocklist.Exists("TEST.BLOCKED.COM."))
	assert.True(t, blocklist.Exists("Test.Blocked.Com."))
}

func Test_BlockList_FastPath(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_fastpath")

	blocklist := New(cfg)

	// Test with empty blocklist - should use fast path
	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ch.Request = req

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	// With empty blocklist, ServeDNS should call Next and not write any response
	blocklist.ServeDNS(context.Background(), ch)
	assert.Nil(t, mw.Msg(), "No response should be written for empty blocklist")

	// Now add an entry and verify it blocks
	blocklist.Set("blocked.com.")
	req.SetQuestion("blocked.com.", dns.TypeA)
	blocklist.ServeDNS(context.Background(), ch)
	assert.NotNil(t, mw.Msg(), "Response should be written for blocked domain")
}
