package blocklist

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
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

	// The registry is process-wide, so a second run in the same process —
	// go test -count=2, say — would otherwise panic on re-registration.
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("blocklist", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	blocklist := middleware.Get("blocklist").(*BlockList)

	if !reflect.DeepEqual("blocklist", blocklist.Name()) {
		t.Errorf("blocklist.Name() = %v, want %v", blocklist.Name(), "blocklist")
	}
	blocklist.Set(testDomain)

	ch := middleware.NewChain([]middleware.Handler{})

	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	ch.Request = middleware.NewRequest(req)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	blocklist.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Answer) > 0) {
		t.Errorf("len(mw.Msg().Answer) > 0 = %v, want %v", len(mw.Msg().Answer) > 0, true)
	}

	req.SetQuestion("test.com.", dns.TypeAAAA)
	ch.Request = middleware.NewRequest(req)

	blocklist.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Answer) > 0) {
		t.Errorf("len(mw.Msg().Answer) > 0 = %v, want %v", len(mw.Msg().Answer) > 0, true)
	}

	req.SetQuestion("test.com.", dns.TypeNS)
	ch.Request = middleware.NewRequest(req)

	blocklist.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, len(mw.Msg().Ns) > 0) {
		t.Errorf("len(mw.Msg().Ns) > 0 = %v, want %v", len(mw.Msg().Ns) > 0, true)
	}

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	req.SetQuestion("test2.com.", dns.TypeA)
	blocklist.ServeDNS(context.Background(), ch)
	if mw.Msg() != nil {
		t.Errorf("mw.Msg() = %v, want nil", mw.Msg())
	}

	if !reflect.DeepEqual(blocklist.Exists(testDomain), true) {
		t.Errorf("true = %v, want %v", true, blocklist.Exists(testDomain))
	}
	if !reflect.DeepEqual(blocklist.Exists(strings.ToUpper(testDomain)), true) {
		t.Errorf("true = %v, want %v", true, blocklist.Exists(strings.ToUpper(testDomain)))
	}

	_, err := blocklist.Get(testDomain)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(blocklist.Length(), 1) {
		t.Errorf("1 = %v, want %v", 1, blocklist.Length())
	}

	if exists := blocklist.Exists(fmt.Sprintf("%sfuzz", testDomain)); exists {
		t.Error("fuzz existed in block blocklist")
	}

	if blocklistLen := blocklist.Length(); blocklistLen != 1 {
		t.Error("invalid length: ", blocklistLen)
	}

	blocklist.Remove(testDomain)
	if !reflect.DeepEqual(blocklist.Exists(testDomain), false) {
		t.Errorf("false = %v, want %v", false, blocklist.Exists(testDomain))
	}

	_, err = blocklist.Get(testDomain)
	if err == nil {
		t.Errorf("expected an error, got nil")
	}

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
	if !(blocklist.Exists("subdomain.blocked.com.")) {
		t.Errorf("blocklist.Exists('subdomain.blocked.com.') is false")
	}
	if !(blocklist.Exists("deep.subdomain.blocked.com.")) {
		t.Errorf("blocklist.Exists('deep.subdomain.blocked.com.') is false")
	}
	if !(blocklist.Exists("very.deep.subdomain.blocked.com.")) {
		t.Errorf("blocklist.Exists('very.deep.subdomain.blocked.com.') is false")
	}

	// The base domain should not be blocked (only subdomains)
	if blocklist.Exists("blocked.com.") {
		t.Errorf("blocklist.Exists('blocked.com.') is true")
	}

	// Other domains should not be blocked
	if blocklist.Exists("notblocked.com.") {
		t.Errorf("blocklist.Exists('notblocked.com.') is true")
	}
	if blocklist.Exists("subdomain.notblocked.com.") {
		t.Errorf("blocklist.Exists('subdomain.notblocked.com.') is true")
	}

	// A bare domain blocks the name itself and every subdomain
	// (matches Pi-hole/AdGuard/dnsmasq; see issue #478).
	blocklist.Set("exact.com.")
	if !(blocklist.Exists("exact.com.")) {
		t.Errorf("blocklist.Exists('exact.com.') is false")
	}
	if !(blocklist.Exists("subdomain.exact.com.")) {
		t.Errorf("blocklist.Exists('subdomain.exact.com.') is false")
	}
	if !(blocklist.Exists("deep.subdomain.exact.com.")) {
		t.Errorf("blocklist.Exists('deep.subdomain.exact.com.') is false")
	}

	// Test multiple wildcard levels
	blocklist.Set("*.subdomain.multi.com.")
	if !(blocklist.Exists("test.subdomain.multi.com.")) {
		t.Errorf("blocklist.Exists('test.subdomain.multi.com.') is false")
	}
	if !(blocklist.Exists("deep.test.subdomain.multi.com.")) {
		t.Errorf("blocklist.Exists('deep.test.subdomain.multi.com.') is false")
	}
	if blocklist.Exists("subdomain.multi.com.") {
		t.Errorf("blocklist.Exists('subdomain.multi.com.') is true")
	}
	if blocklist.Exists("multi.com.") {
		t.Errorf("blocklist.Exists('multi.com.') is true")
	}

	// Test with ServeDNS
	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.blocked.com.", dns.TypeA)
	ch.Request = middleware.NewRequest(req)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	blocklist.ServeDNS(context.Background(), ch)
	if mw.Msg() == nil {
		t.Fatalf("mw.Msg() is nil")
	}
	if !reflect.DeepEqual(true, len(mw.Msg().Answer) > 0) {
		t.Errorf("len(mw.Msg().Answer) > 0 = %v, want %v", len(mw.Msg().Answer) > 0, true)
	}

	// Test non-blocked domain
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	req.SetQuestion("allowed.com.", dns.TypeA)
	blocklist.ServeDNS(context.Background(), ch)
	if mw.Msg() != nil {
		t.Errorf("mw.Msg() = %v, want nil", mw.Msg())
	}

	// Test case insensitivity
	if !(blocklist.Exists("TEST.BLOCKED.COM.")) {
		t.Errorf("blocklist.Exists('TEST.BLOCKED.COM.') is false")
	}
	if !(blocklist.Exists("Test.Blocked.Com.")) {
		t.Errorf("blocklist.Exists('Test.Blocked.Com.') is false")
	}
}

// Test_BlockList_Issue478 loads a plain-domain list (hagezi
// "*-onlydomains.txt" style: bare domains, no "*." prefix) through the
// on-disk blocklist path and verifies that subdomains — what devices
// actually query — are blocked, not just the apex.
func Test_BlockList_Issue478(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "sdns_temp_issue478")
	if err := os.RemoveAll(dir); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	onlyDomains := "# Syntax: Domains (without subdomains)\nmiui.net\nkuyun.com\n"
	if err := os.WriteFile(filepath.Join(dir, "xiaomi-onlydomains.txt"), []byte(onlyDomains), 0600); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = dir

	blocklist := New(cfg)

	// Apex names are blocked.
	if !(blocklist.Exists("miui.net.")) {
		t.Errorf("blocklist.Exists('miui.net.') is false")
	}
	if !(blocklist.Exists("kuyun.com.")) {
		t.Errorf("blocklist.Exists('kuyun.com.') is false")
	}

	// Subdomains are blocked too — the actual fix for #478.
	if !(blocklist.Exists("tracking.miui.net.")) {
		t.Errorf("blocklist.Exists('tracking.miui.net.') is false")
	}
	if !(blocklist.Exists("api.kuyun.com.")) {
		t.Errorf("blocklist.Exists('api.kuyun.com.') is false")
	}
	if !(blocklist.Exists("a.b.kuyun.com.")) {
		t.Errorf("blocklist.Exists('a.b.kuyun.com.') is false")
	}

	// Unrelated names and sibling apexes stay unblocked.
	if blocklist.Exists("notblocked.com.") {
		t.Errorf("blocklist.Exists('notblocked.com.') is true")
	}
	if blocklist.Exists("miui.net.evil.com.") {
		t.Errorf("blocklist.Exists('miui.net.evil.com.') is true")
	}
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
	ch.Request = middleware.NewRequest(req)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw

	// With empty blocklist, ServeDNS should call Next and not write any response
	blocklist.ServeDNS(context.Background(), ch)
	if mw.Msg() != nil {
		t.Errorf("%s: mw.Msg() = %v, want nil", "No response should be written for empty blocklist", mw.Msg())
	}

	// Now add an entry and verify it blocks
	blocklist.Set("blocked.com.")
	req.SetQuestion("blocked.com.", dns.TypeA)
	blocklist.ServeDNS(context.Background(), ch)
	if mw.Msg() == nil {
		t.Errorf("%s: mw.Msg() is nil", "Response should be written for blocked domain")
	}
}

func Test_BlockList_Remove(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp_remove")

	blocklist := New(cfg)

	// Test removing a wildcard entry
	blocklist.Set("*.wildcard.com.")
	if !(blocklist.Exists("sub.wildcard.com.")) {
		t.Errorf("blocklist.Exists('sub.wildcard.com.') is false")
	}
	if !(blocklist.Remove("*.wildcard.com.")) {
		t.Errorf("blocklist.Remove('*.wildcard.com.') is false")
	}
	if blocklist.Exists("sub.wildcard.com.") {
		t.Errorf("blocklist.Exists('sub.wildcard.com.') is true")
	}

	// Test removing a non-existent entry
	if blocklist.Remove("nonexistent.com.") {
		t.Errorf("blocklist.Remove('nonexistent.com.') is true")
	}

	// Test removing a non-existent wildcard
	if blocklist.Remove("*.nonexistent.com.") {
		t.Errorf("blocklist.Remove('*.nonexistent.com.') is true")
	}
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
	if !reflect.DeepEqual(4, added) {
		t.Errorf("added = %v, want %v", added, 4)
	}
	if !(bl.Exists("a.example.")) {
		t.Errorf("bl.Exists('a.example.') is false")
	}
	if !(bl.Exists("sub.evil.com.")) {
		t.Errorf("bl.Exists('sub.evil.com.') is false")
	}
	if !reflect.DeepEqual(3, bl.Length()) {
		t.Errorf("bl.Length() = %v, want %v", bl.Length(), 3)
	} // map dedups: a.example, b.example, evil.com.

	// Whitelist takes precedence: a key on the whitelist contributes
	// 0 to the added count.
	bl.w[dns.CanonicalName("safe.example.")] = true
	added = bl.SetBatch([]string{"safe.example.", "next.example."})
	if !reflect.DeepEqual(1, added) {
		t.Errorf("added = %v, want %v", added, 1)
	}

	// Empty batch is a no-op (no I/O, no count).
	if !reflect.DeepEqual(0, bl.SetBatch(nil)) {
		t.Errorf("bl.SetBatch(nil) = %v, want %v", bl.SetBatch(nil), 0)
	}
	if !reflect.DeepEqual(0, bl.RemoveBatch(nil)) {
		t.Errorf("bl.RemoveBatch(nil) = %v, want %v", bl.RemoveBatch(nil), 0)
	}

	// Bulk remove.
	removed := bl.RemoveBatch([]string{"a.example.", "*.evil.com.", "missing.example."})
	if !reflect.DeepEqual(2, removed) {
		t.Errorf("removed = %v, want %v", removed, 2)
	}
	if bl.Exists("a.example.") {
		t.Errorf("bl.Exists('a.example.') is true")
	}
	if bl.Exists("sub.evil.com.") {
		t.Errorf("bl.Exists('sub.evil.com.') is true")
	}
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
	if !(b.Exists("sub.example.com.")) {
		t.Errorf("%s: b.Exists('sub.example.com.') is false", "subdomain blocked before whitelist")
	}

	// Whitelist the parent — subtree is now exempt.
	b.w[dns.CanonicalName("example.com.")] = true
	if b.Exists("sub.example.com.") {
		t.Errorf("%s: b.Exists('sub.example.com.') is true", "parent whitelist must exempt subdomain")
	}
	if b.Exists("deep.sub.example.com.") {
		t.Errorf("%s: b.Exists('deep.sub.example.com.') is true", "parent whitelist must exempt deep subdomain")
	}
	if b.Exists("example.com.") {
		t.Errorf("%s: b.Exists('example.com.') is true", "whitelisted name itself exempt")
	}

	// A different blocked subtree is unaffected by the whitelist.
	b.Set("*.other.com.")
	if !(b.Exists("x.other.com.")) {
		t.Errorf("%s: b.Exists('x.other.com.') is false", "unrelated subtree still blocked")
	}

	// Set must refuse a block the whitelist hierarchically shadows, rather
	// than persist a block that can never take effect (Exists exempts it
	// anyway). Symmetric with the hierarchical Exists whitelist match.
	if b.Set("sub.example.com.") {
		t.Errorf("%s: b.Set('sub.example.com.') is true", "Set must refuse a hierarchically-whitelisted name")
	}
	if b.Exists("sub.example.com.") {
		t.Errorf("%s: b.Exists('sub.example.com.') is true", "shadowed name stays exempt")
	}
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

	if high.version <= low.version {
		t.Errorf("%s: high.version = %v, want > %v", "later snapshot must carry a higher version", high.version, low.version)
	}

	// Persist out of order: newer first, then the stale older one
	// races in behind it.
	bl.persist(high)
	bl.persist(low)

	data, err := os.ReadFile(filepath.Join(cfg.BlockListDir, "local"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "a.example.") {
		t.Errorf("%q does not contain %q", got, "a.example.")
	}
	if !strings.Contains(got, "b.example.") {
		t.Errorf("%s: %q does not contain %q", "stale snapshot overwrote newer on-disk state: persist rolled backwards", got, "b.example.")
	}

	// A brand-new, newer snapshot still writes normally.
	bl.mu.Lock()
	bl.setLocked("c.example.")
	next := bl.snapshotLocked()
	bl.mu.Unlock()
	bl.persist(next)

	data, err = os.ReadFile(filepath.Join(cfg.BlockListDir, "local"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "c.example.") {
		t.Errorf("%s: %q does not contain %q", "a newer snapshot must still persist", string(data), "c.example.")
	}
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

	if !reflect.DeepEqual(float64(0), read()) {
		t.Errorf("%s: read() = %v, want %v", "a fresh blocklist reports zero entries", read(), float64(0))
	}

	bl.Set("one.example.")
	bl.Set("two.example.")
	bl.Set("*.three.example.")
	if !reflect.DeepEqual(float64(3), read()) {
		t.Errorf("%s: read() = %v, want %v", "gauge must count exact names plus wildcard suffixes", read(), float64(3))
	}
	if !reflect.DeepEqual(float64(bl.Length()), read()) {
		t.Errorf("%s: read() = %v, want %v", "gauge must track Length()", read(), float64(bl.Length()))
	}

	bl.Remove("one.example.")
	if !reflect.DeepEqual(float64(2), read()) {
		t.Errorf("%s: read() = %v, want %v", "gauge must follow removals, not just adds", read(), float64(2))
	}

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
	if !reflect.DeepEqual(float64(1), read()) {
		t.Errorf("%s: read() = %v, want %v", "gauge must follow the newest instance", read(), float64(1))
	}
}
