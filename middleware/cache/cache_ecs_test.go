package cache

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	dto "github.com/prometheus/client_model/go"
	"github.com/semihalev/sdns/config"
	internalcache "github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeECSTestConfig builds a config with ECS enabled at /24 IPv4
// and /56 IPv6 ceilings, matching the defaults the production
// builder applies. Tests opt into specific cardinality knobs via
// the returned config.
func makeECSTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := makeTestConfig()
	cfg.ECS = config.ECSConfig{
		Enabled:      true,
		ForwardV4Max: 24,
		ForwardV6Max: 56,
		MinScopeV4:   24,
		MinScopeV6:   56,
	}
	return cfg
}

// reqWithECS builds an A query for `name` carrying an ECS option
// at the requested family / netmask / address — mirrors what the
// edns middleware would leave on req.Extra after clamping.
func reqWithECS(name string, family uint16, src uint8, addr string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(4096, false)
	opt := req.IsEdns0()
	parsed := net.ParseIP(addr)
	if family == 1 {
		parsed = parsed.To4()
	}
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: family,
		SourceNetmask: src, SourceScope: 0,
		Address: parsed,
	})
	return req
}

// reply builds an upstream response for `req` with one A record and
// (optionally) an ECS SCOPE the test wants to simulate.
func reply(req *dns.Msg, aRecord string, scopeNetmask uint8) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = []dns.RR{
		makeRR(req.Question[0].Name + " 300 IN A " + aRecord),
	}
	if scopeNetmask > 0 {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		// Mirror the request's ECS Source so RFC 7871 §7.1.2 is
		// satisfied: SCOPE never wider than SOURCE.
		var srcAddr net.IP
		var family uint16
		if reqOpt := req.IsEdns0(); reqOpt != nil {
			for _, opt := range reqOpt.Option {
				if v, ok := opt.(*dns.EDNS0_SUBNET); ok {
					srcAddr = v.Address
					family = v.Family
					break
				}
			}
		}
		o.Option = []dns.EDNS0{&dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: family,
			SourceNetmask: scopeNetmask,
			SourceScope:   scopeNetmask,
			Address:       srcAddr,
		}}
		m.Extra = []dns.RR{o}
	}
	return m
}

// echoHandler is a downstream middleware that returns a canned A
// record plus the ECS SCOPE the test asked for. Records how many
// times it was invoked so dedup / cache-hit semantics can be
// asserted from the test side.
type echoHandler struct {
	aRecord    string
	scopeBits  uint8 // 0 = no SCOPE (treated as shared by cache)
	mu         sync.Mutex
	callCount  int
	lastClient string
}

func (h *echoHandler) ServeDNS(_ context.Context, ch *middleware.Chain) {
	h.mu.Lock()
	h.callCount++
	h.lastClient = ch.Writer.RemoteAddr().String()
	h.mu.Unlock()

	resp := reply(ch.Request, h.aRecord, h.scopeBits)
	_ = ch.Writer.WriteMsg(resp)
}

func (h *echoHandler) Name() string { return "echo" }

func (h *echoHandler) Calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.callCount
}

// answerA returns the first A record on the response, or "" if
// none. Tests use this as the proxy for "did the client get
// audience-A's answer or audience-B's?"
func answerA(m *dns.Msg) string {
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// sendAndExpect runs `req` through `c` + `h`, returning the message
// the client would have received.
//
// Drives the chain with ch.Next so the chain index advances through
// the handlers normally. Calling c.ServeDNS directly would dispatch
// the cache at chain index 0 — then the cache's own ch.Next would
// re-dispatch index 0 (itself) instead of advancing to h, causing
// recursive entry on the same dedup key. The follower path would
// then wait 15 s for the leader to release.
func sendAndExpect(t *testing.T, c *Cache, h middleware.Handler, req *dns.Msg, clientIP string) *dns.Msg {
	t.Helper()
	mw := mock.NewWriter("udp", clientIP+":0")
	ch := middleware.NewChain([]middleware.Handler{c, h})
	ch.Reset(mw, req)
	ch.Next(context.Background())
	require.True(t, mw.Written(), "writer was not written")
	return mw.Msg()
}

// TestECSCache_NoCrossContamination is the verbatim #417 regression.
// Two clients in different /24s query the same name; each should see
// their own audience's answer, never the other's.
func TestECSCache_NoCrossContamination(t *testing.T) {
	cfg := makeECSTestConfig(t)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Two responses keyed by client subnet. We swap which is "live"
	// by mutating echoHandler.aRecord between calls.
	h := &echoHandler{aRecord: "10.20.30.40", scopeBits: 24}

	// First: client A in 203.0.113.0/24 gets 10.20.30.40 (cached
	// under scope 203.0.113.0/24).
	respA := sendAndExpect(t, c, h, reqWithECS("cdn.example.", 1, 24, "203.0.113.0"), "203.0.113.5")
	assert.Equal(t, "10.20.30.40", answerA(respA), "client A first lookup")
	require.Equal(t, 1, h.Calls(), "upstream called once for client A")

	// Authority now answers a different address for the next miss.
	h.aRecord = "10.20.30.99"

	// Second: client B in 198.51.100.0/24 — must NOT see client A's
	// cached answer (#417 regression). The cache miss falls through
	// to the upstream which serves the new audience-B answer.
	respB := sendAndExpect(t, c, h, reqWithECS("cdn.example.", 1, 24, "198.51.100.0"), "198.51.100.5")
	assert.Equal(t, "10.20.30.99", answerA(respB), "client B must NOT inherit client A's cached answer")
	require.Equal(t, 2, h.Calls(), "upstream called once for client B (no cache cross-contamination)")

	// Third: client A again. Must hit the cache (no third upstream
	// call), still serving 10.20.30.40.
	respA2 := sendAndExpect(t, c, h, reqWithECS("cdn.example.", 1, 24, "203.0.113.0"), "203.0.113.5")
	assert.Equal(t, "10.20.30.40", answerA(respA2), "client A second lookup hits scoped cache")
	assert.Equal(t, 2, h.Calls(), "no extra upstream call for client A's cache hit")
}

// TestECSCache_SharedKeyOnGlobalScope verifies that a SCOPE=0
// response is cached under the shared key, so a later non-ECS
// client hits the same entry (RFC 7871 §6 "global" answers).
func TestECSCache_SharedKeyOnGlobalScope(t *testing.T) {
	cfg := makeECSTestConfig(t)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Authority returns NO scope on the response → treat as global.
	h := &echoHandler{aRecord: "10.0.0.1", scopeBits: 0}

	// ECS client populates the cache under the shared key (because
	// the response had SCOPE=0).
	respECS := sendAndExpect(t, c, h, reqWithECS("global.example.", 1, 24, "203.0.113.0"), "203.0.113.5")
	assert.Equal(t, "10.0.0.1", answerA(respECS))
	require.Equal(t, 1, h.Calls())

	// Plain (non-ECS) client must hit the same entry.
	plain := new(dns.Msg)
	plain.SetQuestion("global.example.", dns.TypeA)
	respPlain := sendAndExpect(t, c, h, plain, "10.0.0.2")
	assert.Equal(t, "10.0.0.1", answerA(respPlain), "non-ECS client must hit the SCOPE=0 shared entry")
	assert.Equal(t, 1, h.Calls(), "no extra upstream — shared-key hit")
}

// TestECSCache_PreStage2EntriesStillHit pins migration safety: a
// cache entry written by today's shared-key path (the test seeds
// the store directly with the unscoped Key) must still hit on a
// later non-ECS lookup. The Stage 2 hash routing falls through to
// the same Key() for Scope.IsZero(), but verifying end-to-end here
// catches accidental key drift.
func TestECSCache_PreStage2EntriesStillHit(t *testing.T) {
	cfg := makeECSTestConfig(t)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Seed the cache as the pre-Stage-2 code would have done.
	req := new(dns.Msg)
	req.SetQuestion("legacy.example.", dns.TypeA)
	pre := reply(req, "192.0.2.50", 0)
	sharedKey := internalcache.Key(req.Question[0], false)
	c.store.SetFromResponseWithKey(sharedKey, pre)

	// Plain client lookup hits without an upstream call.
	h := &echoHandler{aRecord: "should-not-be-used", scopeBits: 0}
	resp := sendAndExpect(t, c, h, req, "10.0.0.7")
	assert.Equal(t, "192.0.2.50", answerA(resp))
	assert.Equal(t, 0, h.Calls(), "pre-Stage-2 entry must hit without upstream")
}

// TestECSCache_SupernetHit covers the longest-prefix-match fallback:
// an entry cached at /22 should serve a /24 client whose address
// falls inside that /22 supernet (the cache probes /24 first, then
// /23, then /22).
func TestECSCache_SupernetHit(t *testing.T) {
	cfg := makeECSTestConfig(t)
	cfg.ECS.MinScopeV4 = 22 // allow lookups to widen down to /22
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Seed at /22 directly so the test doesn't depend on routing a
	// matching SCOPE through the writer path. The shape mirrors
	// what ResponseWriter.WriteMsg would have stored.
	req := new(dns.Msg)
	req.SetQuestion("super.example.", dns.TypeA)
	scope, err := netip.ParsePrefix("203.0.112.0/22")
	require.NoError(t, err)
	key := CacheKey{Question: req.Question[0], CD: false, Scope: scope}.Hash()
	c.store.SetFromResponseScoped(key, reply(req, "10.1.1.1", 22))

	// Client at 203.0.113.42 — its /24 is 203.0.113.0, which falls
	// inside 203.0.112.0/22. Lookup probes /24 (miss), /23 (miss),
	// /22 (hit).
	h := &echoHandler{aRecord: "should-not-be-used", scopeBits: 0}
	resp := sendAndExpect(t, c, h, reqWithECS("super.example.", 1, 24, "203.0.113.0"), "203.0.113.42")
	assert.Equal(t, "10.1.1.1", answerA(resp))
	assert.Equal(t, 0, h.Calls(), "supernet probe must hit without upstream")
}

// TestECSCache_PolicyOffBypassesEverything: even an ECS-laden
// request hits the shared-key path bit-for-bit when [ecs].enabled
// is false. Stage 2 does not change behaviour for operators that
// haven't opted in.
func TestECSCache_PolicyOffBypassesEverything(t *testing.T) {
	cfg := makeTestConfig() // ECS unset → disabled
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	h := &echoHandler{aRecord: "10.10.10.10", scopeBits: 24}

	// Two clients in different /24s with ECS in the request still
	// see the same cached answer — because policy is off and the
	// cache keys both under the shared key.
	respA := sendAndExpect(t, c, h, reqWithECS("nopolicy.example.", 1, 24, "203.0.113.0"), "203.0.113.5")
	assert.Equal(t, "10.10.10.10", answerA(respA))
	require.Equal(t, 1, h.Calls())

	h.aRecord = "10.10.10.99" // never observed because cache hits
	respB := sendAndExpect(t, c, h, reqWithECS("nopolicy.example.", 1, 24, "198.51.100.0"), "198.51.100.5")
	assert.Equal(t, "10.10.10.10", answerA(respB), "policy off → client B sees client A's cached answer (today's behaviour)")
	assert.Equal(t, 1, h.Calls(), "policy off → no extra upstream call")
}

// TestECSCache_ScopedEntryNotPrefetched: a scoped entry's
// PrefetchEligible() must return false so the prefetch worker
// (which has no client IP) doesn't refresh it as a shared-key
// answer and pollute the scope.
func TestECSCache_ScopedEntryNotPrefetched(t *testing.T) {
	scoped := NewScopedCacheEntry(new(dns.Msg), 60_000_000_000, 0)
	if scoped.PrefetchEligible() {
		t.Errorf("scoped entry must NOT be prefetch-eligible")
	}
	unscoped := NewCacheEntry(new(dns.Msg), 60_000_000_000, 0)
	if !unscoped.PrefetchEligible() {
		t.Errorf("unscoped entry must be prefetch-eligible")
	}
}

// TestECSCache_PurgeRemovesScopedEntries pins the ultrareview P2
// fix: Store.Purge must also remove ECS-keyed entries, not just
// the two unscoped CD keys. Otherwise an API-triggered purge
// reports success while stale geo-tailored answers continue to
// be served until their TTL expires.
func TestECSCache_PurgeRemovesScopedEntries(t *testing.T) {
	cfg := makeECSTestConfig(t)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("purge.example.", dns.TypeA)

	// Seed two scoped entries and one unscoped (shared-key) entry
	// for the same qname/qtype/qclass.
	for _, addr := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		scope := netip.MustParsePrefix(addr)
		key := CacheKey{Question: req.Question[0], CD: false, Scope: scope}.Hash()
		c.store.SetFromResponseScoped(key, reply(req, "10.0.0.1", 24))
		if _, ok := c.store.LookupByKey(key); !ok {
			t.Fatalf("scoped seed for %s did not land in cache", addr)
		}
	}
	sharedKey := CacheKey{Question: req.Question[0], CD: false}.Hash()
	c.store.SetFromResponseWithKey(sharedKey, reply(req, "10.0.0.99", 0))

	c.store.Purge(req.Question[0])

	if _, ok := c.store.LookupByKey(sharedKey); ok {
		t.Errorf("shared-key entry survived Purge")
	}
	for _, addr := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		scope := netip.MustParsePrefix(addr)
		key := CacheKey{Question: req.Question[0], CD: false, Scope: scope}.Hash()
		if _, ok := c.store.LookupByKey(key); ok {
			t.Errorf("scoped entry %s survived Purge", addr)
		}
	}
}

// TestECSCache_BroaderScopeOnNormalClientHits pins the fifth-round
// ultrareview P2 fix: when an authority returns a broader-than-min
// SCOPE for a normal client (the common case — a /24 source with a
// /20 SCOPE response, meaning "this answer covers the whole /20"),
// the inserted /20 entry must be reachable by the same /24 client
// on its next query. The earlier loop capped probes at min_scope_v4
// = 24, so a /24 client only probed /24 and never found the /20
// entry it had just caused to be stored.
//
// Distinct from BroaderThanMinClientScopeHits: that test exercises
// a /20 *client* source. This one exercises the much more common
// /24 *client* source with a broader *response* SCOPE.
func TestECSCache_BroaderScopeOnNormalClientHits(t *testing.T) {
	cfg := makeECSTestConfig(t) // defaults: ForwardV4Max=24, MinScopeV4=24
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Authority claims the answer is valid for the whole /20 around
	// the client, even though the client itself sent a /24 source.
	// RFC 7871 allows SCOPE wider than SOURCE (it's the authority
	// saying "I'd give the same answer to a broader audience"); only
	// SCOPE > SOURCE is the RFC violation that ClampScope clamps.
	h := &echoHandler{aRecord: "10.1.2.3", scopeBits: 20}

	// First /24 query inserts the /20 entry.
	respA := sendAndExpect(t, c, h,
		reqWithECS("broad-scope.example.", 1, 24, "203.0.112.0"),
		"203.0.112.5")
	assert.Equal(t, "10.1.2.3", answerA(respA))
	require.Equal(t, 1, h.Calls())

	// Second /24 query from the same client must HIT — same source
	// prefix, the stored /20 entry covers it.
	h.aRecord = "should-not-be-used"
	respB := sendAndExpect(t, c, h,
		reqWithECS("broad-scope.example.", 1, 24, "203.0.112.0"),
		"203.0.112.5")
	assert.Equal(t, "10.1.2.3", answerA(respB),
		"second /24 query missed the /20 entry the first query inserted")
	assert.Equal(t, 1, h.Calls(),
		"second /24 query went upstream instead of hitting the broader cached entry")

	// A different /24 *within* the same /20 must also hit — that's
	// the whole point of caching at a broader SCOPE.
	respC := sendAndExpect(t, c, h,
		reqWithECS("broad-scope.example.", 1, 24, "203.0.113.0"),
		"203.0.113.42")
	assert.Equal(t, "10.1.2.3", answerA(respC),
		"sibling /24 within the same /20 missed the broader entry")
	assert.Equal(t, 1, h.Calls(), "sibling /24 went upstream needlessly")
}

// TestECSCache_BroaderThanMinClientScopeHits pins the fourth-round
// ultrareview P2 fix: a client whose source prefix is broader than
// the policy's min_scope (e.g. /20 with min_scope_v4=24) must still
// be able to look up an entry it just inserted. The earlier
// scopedLookup loop's `bits >= minBits` bound did zero probes when
// the client's own bits fell below min_scope, even though Policy.Clamp
// passed the /20 source through unchanged and the insert path
// happily stored a /20 entry. After the fifth-round fix lookup
// probes down to /1 unconditionally, so this is implicitly covered;
// kept as a focused regression for the broader-client axis.
func TestECSCache_BroaderThanMinClientScopeHits(t *testing.T) {
	cfg := makeECSTestConfig(t) // defaults: ForwardV4Max=24, MinScopeV4=24
	cfg.ECS.ForwardV4Max = 20   // allow /20 sources through
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// echoHandler returns SCOPE=20 to match the client's /20 source —
	// RFC 7871 §7.1.2 forbids SCOPE > SOURCE, so /20 is the strictest
	// scope this authority can claim for this audience.
	h := &echoHandler{aRecord: "10.20.30.40", scopeBits: 20}

	// First request inserts the /20 entry.
	req := reqWithECS("broad.example.", 1, 20, "203.0.96.0")
	respA := sendAndExpect(t, c, h, req, "203.0.96.5")
	assert.Equal(t, "10.20.30.40", answerA(respA))
	require.Equal(t, 1, h.Calls())

	// Second request from the same /20 must HIT the cache.
	h.aRecord = "should-not-be-used"
	respB := sendAndExpect(t, c, h, reqWithECS("broad.example.", 1, 20, "203.0.96.0"), "203.0.96.5")
	assert.Equal(t, "10.20.30.40", answerA(respB), "second /20 query missed the /20 entry just inserted")
	assert.Equal(t, 1, h.Calls(), "second /20 query went upstream instead of hitting the cache")
}

// TestECSCache_LookupsMetricCountsOnlyECSPaths pins the sixth-round
// ultrareview P3 fix: dns_cache_ecs_lookups_total{outcome=...} must
// count every request that went through the ECS-aware lookup path
// exactly once (no skipped misses). Non-ECS lookups stay on the
// existing dns_cache_hits_total / dns_cache_misses_total counters
// — we don't duplicate them here.
func TestECSCache_LookupsMetricCountsOnlyECSPaths(t *testing.T) {
	cfg := makeECSTestConfig(t)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Counter is package-global; snapshot before / after so we
	// don't depend on whatever previous tests left behind.
	hitScopedBefore := metricValue(t, "hit_scoped")
	hitSharedBefore := metricValue(t, "hit_shared")
	missBefore := metricValue(t, "miss")

	h := &echoHandler{aRecord: "10.20.30.40", scopeBits: 24}

	// (1) ECS request, cache empty → miss, then store.
	_ = sendAndExpect(t, c, h,
		reqWithECS("metric.example.", 1, 24, "203.0.113.0"),
		"203.0.113.5")

	// (2) Same ECS request → hit_scoped.
	_ = sendAndExpect(t, c, h,
		reqWithECS("metric.example.", 1, 24, "203.0.113.0"),
		"203.0.113.5")

	// (3) Non-ECS request — must NOT touch the ECS metric at all.
	plain := new(dns.Msg)
	plain.SetQuestion("metric.example.", dns.TypeA)
	_ = sendAndExpect(t, c, h, plain, "10.0.0.7")

	// (4) Another non-ECS that misses (different qname so no hit).
	plainMiss := new(dns.Msg)
	plainMiss.SetQuestion("absent.example.", dns.TypeA)
	_ = sendAndExpect(t, c, h, plainMiss, "10.0.0.8")

	gotMiss := metricValue(t, "miss") - missBefore
	gotHitScoped := metricValue(t, "hit_scoped") - hitScopedBefore
	gotHitShared := metricValue(t, "hit_shared") - hitSharedBefore

	if gotMiss != 1 {
		t.Errorf("miss delta = %v, want 1", gotMiss)
	}
	if gotHitScoped != 1 {
		t.Errorf("hit_scoped delta = %v, want 1", gotHitScoped)
	}
	if gotHitShared != 0 {
		t.Errorf("hit_shared delta = %v, want 0", gotHitShared)
	}
}

// metricValue reads the current counter value for an ecsLookups
// outcome. Returns 0 if the label has never been observed.
func metricValue(t *testing.T, outcome string) float64 {
	t.Helper()
	m, err := ecsLookups.GetMetricWithLabelValues(outcome)
	if err != nil {
		t.Fatalf("get metric: %v", err)
	}
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return pb.GetCounter().GetValue()
}

// TestECSCache_BuildPolicyFailClosed covers the error path of
// buildCacheECSPolicy: a malformed [ecs] config (bad CIDR in
// client_networks, out-of-range forward ceiling, etc.) disables
// ECS-aware caching with a single log line. The cache continues
// to operate, just on the unscoped key path — matching what
// the edns middleware does on the forwarding side.
func TestECSCache_BuildPolicyFailClosed(t *testing.T) {
	cfg := makeTestConfig()
	cfg.ECS = config.ECSConfig{
		Enabled:        true,
		ForwardV4Max:   24,
		ClientNetworks: []string{"10.0.0.0/33"}, // intentional typo
	}
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	if c.ecsPolicy != nil {
		t.Fatal("invalid client_networks must disable ECS-aware caching")
	}

	// Non-ECS traffic still works (the path the cache falls back to).
	h := &echoHandler{aRecord: "10.0.0.1", scopeBits: 0}
	plain := new(dns.Msg)
	plain.SetQuestion("disabled-policy.example.", dns.TypeA)
	resp := sendAndExpect(t, c, h, plain, "10.0.0.7")
	assert.Equal(t, "10.0.0.1", answerA(resp))

	// And an ECS-bearing request goes through the shared-key path
	// because requestScope short-circuits on c.ecsPolicy == nil.
	ecs := reqWithECS("disabled-policy.example.", 1, 24, "203.0.113.0")
	resp2 := sendAndExpect(t, c, h, ecs, "203.0.113.5")
	assert.Equal(t, "10.0.0.1", answerA(resp2),
		"ECS request with disabled policy must hit the shared-key entry")
}

// TestECSCache_RequestScopeMalformedReturnsZero covers the
// defensive branches of requestScope: a client whose ECS option
// has an unparseable address, or an OPT carrying no ECS, must
// fall through to the unscoped (shared-key) lookup path rather
// than panicking or building a bogus prefix.
func TestECSCache_RequestScopeMalformedReturnsZero(t *testing.T) {
	cfg := makeECSTestConfig(t)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	client := netip.MustParseAddr("203.0.113.5")

	t.Run("nil OPT", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("noopt.example.", dns.TypeA)
		if got := c.requestScope(req, client); got.IsValid() {
			t.Errorf("expected zero prefix, got %s", got)
		}
	})

	t.Run("OPT without ECS option", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("nosubnet.example.", dns.TypeA)
		req.SetEdns0(4096, false)
		req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_COOKIE{
			Code: dns.EDNS0COOKIE, Cookie: "deadbeefcafefade",
		})
		if got := c.requestScope(req, client); got.IsValid() {
			t.Errorf("expected zero prefix, got %s", got)
		}
	})

	t.Run("ECS option with empty Address", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("emptyaddr.example.", dns.TypeA)
		req.SetEdns0(4096, false)
		req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
			// Address intentionally nil — AddrFromSlice should fail
			// and requestScope returns the zero prefix.
		})
		if got := c.requestScope(req, client); got.IsValid() {
			t.Errorf("expected zero prefix, got %s", got)
		}
	})

	t.Run("ECS option with absurd SourceNetmask", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("badmask.example.", dns.TypeA)
		req.SetEdns0(4096, false)
		req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: 1,
			SourceNetmask: 200, // > 32, Addr.Prefix returns an error
			Address:       net.ParseIP("203.0.113.0").To4(),
		})
		if got := c.requestScope(req, client); got.IsValid() {
			t.Errorf("expected zero prefix, got %s", got)
		}
	})
}

// TestECSCache_PurgeIsCaseInsensitive pins the third-round
// ultrareview P2 fix: the scoped purge sweep compares names
// directly, but cache keys lowercase the name during hashing.
// An entry whose stored Question carries upper-case characters
// (because the upstream response echoed the client's case) must
// still be removed by a purge of the lowercase form.
func TestECSCache_PurgeIsCaseInsensitive(t *testing.T) {
	cfg := makeECSTestConfig(t)
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Seed under the stored Question with mixed case — that's what
	// the cache would record if the client (or upstream response)
	// used mixed case. The hash key itself is case-insensitive
	// (Key + KeyWithPrefix both lowercase during hashing), so the
	// stored question Name diverges from the lowercase form the
	// operator-facing purge API will use.
	req := new(dns.Msg)
	req.SetQuestion("Mixed.Example.", dns.TypeA)
	scope := netip.MustParsePrefix("203.0.113.0/24")
	key := CacheKey{Question: req.Question[0], CD: false, Scope: scope}.Hash()
	c.store.SetFromResponseScoped(key, reply(req, "10.0.0.1", 24))
	require.Truef(t, func() bool { _, ok := c.store.LookupByKey(key); return ok }(),
		"seed did not land in cache")

	// Operator purges via the canonical lowercase FQDN.
	c.store.Purge(dns.Question{
		Name:   "mixed.example.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})

	if _, ok := c.store.LookupByKey(key); ok {
		t.Errorf("scoped entry stored under mixed-case Question survived a lowercase purge")
	}
}

// TestECSCache_CacheLimitTTLCapsScopedWrites pins the ultrareview
// P2 fix: cache_limit_ttl must clamp the TTL of scoped entries so
// a misbehaving upstream sending a multi-hour TTL on a /24 answer
// can't pin that audience to a stale CDN node.
func TestECSCache_CacheLimitTTLCapsScopedWrites(t *testing.T) {
	cfg := makeECSTestConfig(t)
	cfg.ECS.CacheLimitTTL.Duration = 30 * time.Second
	defer os.RemoveAll(cfg.Directory)
	c := New(cfg)
	defer c.Stop()

	// Build a response with a 1-hour TTL — well over the 30 s cap.
	req := new(dns.Msg)
	req.SetQuestion("ttlcap.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{makeRR("ttlcap.example. 3600 IN A 10.0.0.1")}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.Option = []dns.EDNS0{&dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1,
		SourceNetmask: 24, SourceScope: 24,
		Address: net.ParseIP("203.0.113.0").To4(),
	}}
	resp.Extra = []dns.RR{o}

	scope := netip.MustParsePrefix("203.0.113.0/24")
	key := CacheKey{Question: req.Question[0], CD: false, Scope: scope}.Hash()
	c.store.SetFromResponseScoped(key, resp)

	entry, ok := c.store.LookupByKey(key)
	require.True(t, ok, "scoped seed did not land in cache")
	if entry.ttl > cfg.ECS.CacheLimitTTL.Duration {
		t.Errorf("scoped TTL %s exceeded cache_limit_ttl cap %s",
			entry.ttl, cfg.ECS.CacheLimitTTL.Duration)
	}

	// Unscoped writes must NOT be capped — the cap is per
	// CacheConfig.ECSMaxTTL gated by `scoped == true`.
	plainKey := CacheKey{Question: req.Question[0], CD: false}.Hash()
	c.store.SetFromResponseWithKey(plainKey, resp)
	plain, ok := c.store.LookupByKey(plainKey)
	require.True(t, ok)
	if plain.ttl <= cfg.ECS.CacheLimitTTL.Duration {
		t.Errorf("unscoped TTL %s was capped at %s (should not be)",
			plain.ttl, cfg.ECS.CacheLimitTTL.Duration)
	}
}
