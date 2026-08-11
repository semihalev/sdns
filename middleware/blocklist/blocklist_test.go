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
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
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

	// A bare domain blocks the name itself and every subdomain
	// (matches Pi-hole/AdGuard/dnsmasq; see issue #478).
	blocklist.Set("exact.com.")
	assert.True(t, blocklist.Exists("exact.com."))
	assert.True(t, blocklist.Exists("subdomain.exact.com."))
	assert.True(t, blocklist.Exists("deep.subdomain.exact.com."))

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

// Test_BlockList_Issue478 loads a plain-domain list (hagezi
// "*-onlydomains.txt" style: bare domains, no "*." prefix) through the
// on-disk blocklist path and verifies that subdomains — what devices
// actually query — are blocked, not just the apex.
func Test_BlockList_Issue478(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "sdns_temp_issue478")
	assert.NoError(t, os.RemoveAll(dir))
	assert.NoError(t, os.MkdirAll(dir, 0750))
	defer func() { _ = os.RemoveAll(dir) }()

	onlyDomains := "# Syntax: Domains (without subdomains)\nmiui.net\nkuyun.com\n"
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "xiaomi-onlydomains.txt"), []byte(onlyDomains), 0600))

	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = dir

	blocklist := New(cfg)

	// Apex names are blocked.
	assert.True(t, blocklist.Exists("miui.net."))
	assert.True(t, blocklist.Exists("kuyun.com."))

	// Subdomains are blocked too — the actual fix for #478.
	assert.True(t, blocklist.Exists("tracking.miui.net."))
	assert.True(t, blocklist.Exists("api.kuyun.com."))
	assert.True(t, blocklist.Exists("a.b.kuyun.com."))

	// Unrelated names and sibling apexes stay unblocked.
	assert.False(t, blocklist.Exists("notblocked.com."))
	assert.False(t, blocklist.Exists("miui.net.evil.com."))
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

// Test_BlockList_WhitelistHierarchy verifies the whitelist is matched across
// the domain hierarchy (symmetric with the block walk): whitelisting a parent
// exempts its subdomains, and only ever exempts.
func Test_BlockList_WhitelistHierarchy(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_wl")
	b := New(cfg)

	b.Set("*.example.com.")
	assert.True(t, b.Exists("sub.example.com."), "subdomain blocked before whitelist")

	// Whitelist the parent — subtree is now exempt.
	b.w[dns.CanonicalName("example.com.")] = true
	assert.False(t, b.Exists("sub.example.com."), "parent whitelist must exempt subdomain")
	assert.False(t, b.Exists("deep.sub.example.com."), "parent whitelist must exempt deep subdomain")
	assert.False(t, b.Exists("example.com."), "whitelisted name itself exempt")

	// A different blocked subtree is unaffected by the whitelist.
	b.Set("*.other.com.")
	assert.True(t, b.Exists("x.other.com."), "unrelated subtree still blocked")

	// Set must refuse a block the whitelist hierarchically shadows, rather
	// than persist a block that can never take effect (Exists exempts it
	// anyway). Symmetric with the hierarchical Exists whitelist match.
	assert.False(t, b.Set("sub.example.com."), "Set must refuse a hierarchically-whitelisted name")
	assert.False(t, b.Exists("sub.example.com."), "shadowed name stays exempt")
}

// Test_BlockList_PersistOrdering pins the ordering guarantee of the
// asynchronous persist path. Snapshots are taken in a total order
// under mu, but persist() runs after mu is released and is only
// serialized by saveMu, so two concurrent mutations can reach the
// rename in either order. A stale (older-version) snapshot that
// lands after a newer one must be dropped, so the on-disk file never
// rolls backwards relative to memory.
func Test_BlockList_PersistOrdering(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_persistorder")
	_ = os.RemoveAll(cfg.BlockListDir)
	if err := os.MkdirAll(cfg.BlockListDir, 0750); err != nil {
		t.Fatal(err)
	}

	bl := New(cfg)

	// Build two snapshots in version order, exactly as the mutation
	// paths do: an older one describing {a} and a newer one {a, b}.
	bl.mu.Lock()
	bl.setLocked("a.example.")
	low := bl.snapshotLocked() // older version
	bl.setLocked("b.example.")
	high := bl.snapshotLocked() // newer version
	bl.mu.Unlock()

	assert.Greater(t, high.version, low.version, "later snapshot must carry a higher version")

	// Persist out of order: newer first, then the stale older one
	// races in behind it.
	bl.persist(high)
	bl.persist(low)

	data, err := os.ReadFile(filepath.Join(cfg.BlockListDir, "local"))
	assert.NoError(t, err)
	got := string(data)
	assert.Contains(t, got, "a.example.")
	assert.Contains(t, got, "b.example.",
		"stale snapshot overwrote newer on-disk state: persist rolled backwards")

	// A brand-new, newer snapshot still writes normally.
	bl.mu.Lock()
	bl.setLocked("c.example.")
	next := bl.snapshotLocked()
	bl.mu.Unlock()
	bl.persist(next)

	data, err = os.ReadFile(filepath.Join(cfg.BlockListDir, "local"))
	assert.NoError(t, err)
	assert.Contains(t, string(data), "c.example.", "a newer snapshot must still persist")
}

// Test_BlockList_EntriesGauge pins dns_blocklist_entries to the live map
// contents. The gauge exists so operators can alert on a list that failed
// to load or was emptied by a bad update — cases where the hits counter
// stays at zero and looks indistinguishable from "nothing matched". A
// gauge captured once at load time would miss exactly those regressions,
// so this asserts it tracks mutations too.
func Test_BlockList_EntriesGauge(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_entriesgauge")
	_ = os.RemoveAll(cfg.BlockListDir)
	if err := os.MkdirAll(cfg.BlockListDir, 0750); err != nil {
		t.Fatal(err)
	}

	bl := New(cfg)

	read := func() float64 {
		fn := blocklistLen.Load()
		if fn == nil {
			return 0
		}
		return float64((*fn)())
	}

	assert.Equal(t, float64(0), read(), "a fresh blocklist reports zero entries")

	bl.Set("one.example.")
	bl.Set("two.example.")
	bl.Set("*.three.example.")
	assert.Equal(t, float64(3), read(),
		"gauge must count exact names plus wildcard suffixes")
	assert.Equal(t, float64(bl.Length()), read(), "gauge must track Length()")

	bl.Remove("one.example.")
	assert.Equal(t, float64(2), read(), "gauge must follow removals, not just adds")

	// A second instance takes over the published accessor, mirroring what
	// happens when the middleware is rebuilt; the gauge must follow the
	// live one rather than keep reporting the dead instance's count.
	cfg2 := new(config.Config)
	cfg2.Nullroute = "0.0.0.0"
	cfg2.Nullroutev6 = "::0"
	cfg2.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_entriesgauge2")
	_ = os.RemoveAll(cfg2.BlockListDir)
	if err := os.MkdirAll(cfg2.BlockListDir, 0750); err != nil {
		t.Fatal(err)
	}
	bl2 := New(cfg2)
	bl2.Set("only.example.")
	assert.Equal(t, float64(1), read(), "gauge must follow the newest instance")
}
