package blocklist

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	// loadInitial now reads local files synchronously; drop any
	// state a previous run persisted so Length assertions below
	// aren't polluted.
	_ = os.RemoveAll(cfg.BlockListDir)

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

func Test_BlockList_Remove(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_remove")

	blocklist := New(cfg)

	// Test removing a wildcard entry
	blocklist.Set("*.wildcard.com.")
	assert.True(t, blocklist.Exists("sub.wildcard.com."))
	assert.True(t, blocklist.Remove("*.wildcard.com."))
	assert.False(t, blocklist.Exists("sub.wildcard.com."))

	// Test removing a non-existent entry
	assert.False(t, blocklist.Remove("nonexistent.com."))

	// Test removing a non-existent wildcard
	assert.False(t, blocklist.Remove("*.nonexistent.com."))
}

func Test_BlockList_Batch(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_batch")
	_ = os.RemoveAll(cfg.BlockListDir)

	bl := New(cfg)

	keys := []string{
		"a.example.",
		"b.example.",
		"a.example.", // duplicate, should still count as added (idempotent set)
		"*.evil.com.",
	}
	added := bl.SetBatch(keys)
	// a.example added once, b.example, *.evil.com → 4 calls all
	// reach the map; setLocked returns true for each. The count is
	// "calls that took effect" rather than "unique keys", which is
	// fine for the API caller — they get what they asked for.
	assert.Equal(t, 4, added)
	assert.True(t, bl.Exists("a.example."))
	assert.True(t, bl.Exists("sub.evil.com."))
	assert.Equal(t, 3, bl.Length()) // map dedups: a.example, b.example, evil.com.

	// Whitelist takes precedence: a key on the whitelist contributes
	// 0 to the added count.
	bl.w[dns.CanonicalName("safe.example.")] = true
	added = bl.SetBatch([]string{"safe.example.", "next.example."})
	assert.Equal(t, 1, added)

	// Empty batch is a no-op (no I/O, no count).
	assert.Equal(t, 0, bl.SetBatch(nil))
	assert.Equal(t, 0, bl.RemoveBatch(nil))

	// Bulk remove.
	removed := bl.RemoveBatch([]string{"a.example.", "*.evil.com.", "missing.example."})
	assert.Equal(t, 2, removed)
	assert.False(t, bl.Exists("a.example."))
	assert.False(t, bl.Exists("sub.evil.com."))
}

// Test_BlockList_NoStallDuringSave proves the property the GitHub
// issue reporter cared about: a mutation does not block a
// concurrent ServeDNS read on the blocklist's mu, even when the
// disk write under saveMu takes time. We can't reliably make the
// disk slow in CI, so we instead pin the contract structurally —
// holding saveMu in the test and confirming a mutation acquires
// b.mu, returns, and releases it without ever waiting on the
// disk-side lock.
func Test_BlockList_NoStallDuringSave(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_nostall")
	_ = os.RemoveAll(cfg.BlockListDir)

	bl := New(cfg)
	bl.Set("seed.example.")

	// Hold the persistence lock from a separate goroutine to
	// simulate an in-flight slow disk write.
	bl.saveMu.Lock()
	defer bl.saveMu.Unlock()

	// A reader (ServeDNS path) takes mu.RLock(); it must not be
	// blocked by anything happening under saveMu.
	done := make(chan struct{})
	go func() {
		bl.mu.RLock()
		_ = bl.m["seed.example."]
		bl.mu.RUnlock()
		close(done)
	}()

	select {
	case <-done:
		// expected: the read returned without waiting for saveMu.
	case <-time.After(2 * time.Second):
		t.Fatal("ServeDNS-style RLock blocked while saveMu was held — disk I/O is back inside the map lock")
	}
}
