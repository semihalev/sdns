package cache

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

type controllableDeadlineContext struct {
	context.Context
	expired bool
}

func (c *controllableDeadlineContext) Deadline() (time.Time, bool) {
	if c.expired {
		return time.Unix(1, 0), true
	}
	return time.Now().Add(time.Hour), true
}

func staleTestAnswer(req *dns.Msg, address string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: netip.MustParseAddr(address).AsSlice(),
	}}
	return resp
}

func seedStaleEntry(
	t *testing.T,
	c *Cache,
	resp *dns.Msg,
	scope netip.Prefix,
	staleFor time.Duration,
	leaseRemaining time.Duration,
) *CacheEntry {
	t.Helper()
	q := resp.Question[0]
	want := CacheKey{Question: q, CD: resp.CheckingDisabled, Scope: scope}
	entry := NewCacheEntryWithKey(resp, time.Minute, 0, want.Hash())
	if entry == nil {
		t.Fatal("failed to construct stale cache entry")
	}
	entry.scope = normalizeKeyScope(scope)
	entry.stored = time.Now().Add(-time.Minute - staleFor)
	if leaseRemaining != 0 {
		entry.cutUntil = time.Now().Add(leaseRemaining)
	}
	c.store.SetEntryWithKey(want.Hash(), entry, dnsutil.TypeSuccess)
	return entry
}

func runStaleQuery(
	t *testing.T,
	c *Cache,
	req *dns.Msg,
	downstream middleware.Handler,
	ctx context.Context,
) *dns.Msg {
	t.Helper()
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	ch := middleware.NewChain([]middleware.Handler{c, downstream})
	ch.Reset(writer, req)
	ch.Next(ctx)
	if !writer.Written() {
		t.Fatal("query wrote no response")
	}
	return writer.Msg()
}

func servfailHandler(calls *int) middleware.Handler {
	return middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		(*calls)++
		resp := new(dns.Msg)
		resp.SetRcode(ch.Request.Msg(), dns.RcodeServerFailure)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
}

func TestServeStaleOnFreshSERVFAIL(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("stale.example.", dns.TypeA)
	req.SetEdns0(1232, true)
	answer := staleTestAnswer(req, "192.0.2.44")
	answer.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600},
		Ns:  "ns.example.",
	}}
	answer.Extra = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "ns.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 900},
		A:   netip.MustParseAddr("192.0.2.99").AsSlice(),
	}}
	seedStaleEntry(t, c, answer, netip.Prefix{}, time.Second, time.Hour)

	calls := 0
	resp := runStaleQuery(t, c, req, servfailHandler(&calls), context.Background())
	if calls != 1 {
		t.Fatalf("downstream calls = %d, want 1", calls)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("response = rcode %s, answers %d; want stale positive answer", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl != 30 {
				t.Fatalf("%s TTL = %d, want 30", rr.Header().Name, rr.Header().Ttl)
			}
		}
	}
	if ede := dnsutil.GetEDE(resp); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer || ede.ExtraText != "Stale Answer" {
		t.Fatalf("EDE = %+v, want code 3 Stale Answer", ede)
	}
}

func TestServeStaleRespectsLeaseAndOperatorCeiling(t *testing.T) {
	tests := []struct {
		name           string
		maxStale       time.Duration
		staleFor       time.Duration
		leaseRemaining time.Duration
	}{
		{name: "expired delegation lease", staleFor: time.Second, leaseRemaining: -time.Second},
		{name: "operator ceiling", maxStale: time.Minute, staleFor: 2 * time.Minute, leaseRemaining: time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{CacheSize: 1024, ServeStale: true}
			cfg.ServeStaleMaxTTL.Duration = tt.maxStale
			c := New(cfg)
			defer c.Stop()

			req := new(dns.Msg)
			req.SetQuestion("bounded.example.", dns.TypeA)
			req.SetEdns0(1232, false)
			seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.45"), netip.Prefix{}, tt.staleFor, tt.leaseRemaining)

			calls := 0
			resp := runStaleQuery(t, c, req, servfailHandler(&calls), context.Background())
			if resp.Rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
			}
		})
	}
}

func TestServeStaleAdvertisedTTLDoesNotOutliveLease(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("short-lease.example.", dns.TypeA)
	req.SetEdns0(1232, false)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.55"), netip.Prefix{}, time.Second, 2*time.Second)

	calls := 0
	resp := runStaleQuery(t, c, req, servfailHandler(&calls), context.Background())
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("response = rcode %s, answers %d; want stale positive answer", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl > 2 {
		t.Fatalf("stale TTL = %d, must not outlive the 2s delegation lease", ttl)
	}
}

func TestServeStaleRequiresActualSERVFAIL(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("refused.example.", dns.TypeA)
	req.SetEdns0(1232, false)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.56"), netip.Prefix{}, time.Second, time.Hour)

	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetRcode(ch.Request.Msg(), dns.RcodeRefused)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
	resp := runStaleQuery(t, c, req, downstream, context.Background())
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want unchanged REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestServeStaleRejectsNegativeAnswers(t *testing.T) {
	tests := []struct {
		name  string
		rcode int
	}{
		{name: "NXDOMAIN", rcode: dns.RcodeNameError},
		{name: "NODATA", rcode: dns.RcodeSuccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, ServeStale: true})
			defer c.Stop()
			req := new(dns.Msg)
			req.SetQuestion("negative.example.", dns.TypeA)
			req.SetEdns0(1232, false)
			negative := new(dns.Msg)
			negative.SetRcode(req, tt.rcode)
			negative.Ns = []dns.RR{&dns.SOA{
				Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:      "ns.example.",
				Mbox:    "hostmaster.example.",
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  300,
			}}
			seedStaleEntry(t, c, negative, netip.Prefix{}, time.Second, time.Hour)

			calls := 0
			resp := runStaleQuery(t, c, req, servfailHandler(&calls), context.Background())
			if resp.Rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
			}
		})
	}
}

func TestServeStaleDisabledAndFreshEntryUnchanged(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		c := New(&config.Config{CacheSize: 1024})
		defer c.Stop()
		req := new(dns.Msg)
		req.SetQuestion("disabled.example.", dns.TypeA)
		req.SetEdns0(1232, false)
		seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.46"), netip.Prefix{}, time.Second, time.Hour)

		calls := 0
		resp := runStaleQuery(t, c, req, servfailHandler(&calls), context.Background())
		if resp.Rcode != dns.RcodeServerFailure || dnsutil.GetEDE(resp) != nil {
			t.Fatalf("disabled response = rcode %s, EDE %+v; want unchanged SERVFAIL", dns.RcodeToString[resp.Rcode], dnsutil.GetEDE(resp))
		}
	})

	t.Run("fresh entry", func(t *testing.T) {
		c := New(&config.Config{CacheSize: 1024, ServeStale: true})
		defer c.Stop()
		req := new(dns.Msg)
		req.SetQuestion("fresh.example.", dns.TypeA)
		req.SetEdns0(1232, false)
		answer := staleTestAnswer(req, "192.0.2.47")
		c.store.SetFromResponse(answer, false, time.Now().Add(time.Hour))

		calls := 0
		resp := runStaleQuery(t, c, req, servfailHandler(&calls), context.Background())
		if calls != 0 {
			t.Fatalf("fresh cache hit reached downstream %d times", calls)
		}
		if ede := dnsutil.GetEDE(resp); ede != nil {
			t.Fatalf("fresh response carried stale EDE: %+v", ede)
		}
		if resp.Answer[0].Header().Ttl == 30 {
			t.Fatal("fresh response was reshaped with the stale TTL")
		}
	})
}

func TestServeStaleADTracksSignatureValidity(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		expiration time.Time
		wantAD     bool
	}{
		{name: "current signature", expiration: now.Add(time.Hour), wantAD: true},
		{name: "expired signature", expiration: now.Add(-time.Second), wantAD: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, ServeStale: true})
			defer c.Stop()
			req := new(dns.Msg)
			req.SetQuestion("signed.example.", dns.TypeA)
			req.SetEdns0(1232, true)
			answer := staleTestAnswer(req, "192.0.2.48")
			answer.AuthenticatedData = true
			answer.Answer = append(answer.Answer, &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				TypeCovered: dns.TypeA,
				Algorithm:   dns.RSASHA256,
				Labels:      2,
				OrigTtl:     300,
				Expiration:  uint32(tt.expiration.Unix()),       //nolint:gosec // DNS timestamp fixture
				Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // DNS timestamp fixture
				KeyTag:      12345,
				SignerName:  "example.",
				Signature:   "ZmFrZXNpZ25hdHVyZQ==",
			})
			seedStaleEntry(t, c, answer, netip.Prefix{}, time.Second, time.Hour)

			calls := 0
			resp := runStaleQuery(t, c, req, servfailHandler(&calls), context.Background())
			if resp.AuthenticatedData != tt.wantAD {
				t.Fatalf("AD = %v, want %v", resp.AuthenticatedData, tt.wantAD)
			}
		})
	}
}

func TestServeStalePrecedesRFC9520FailureHit(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("failure-hit.example.", dns.TypeA)
	req.SetEdns0(1232, false)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.49"), netip.Prefix{}, time.Second, time.Hour)

	failure := new(dns.Msg)
	failure.SetRcode(req, dns.RcodeServerFailure)
	c.store.RecordFailure(failure, netip.Prefix{}, FailureProvenance("test"), nil)

	calls := 0
	resp := runStaleQuery(t, c, req, middleware.HandlerFunc(func(_ context.Context, _ *middleware.Chain) {
		calls++
	}), context.Background())
	if calls != 0 {
		t.Fatalf("cached failure reached downstream %d times", calls)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want stale success", dns.RcodeToString[resp.Rcode])
	}
	if ede := dnsutil.GetEDE(resp); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer {
		t.Fatalf("EDE = %+v, want stale answer", ede)
	}
}

func TestServeStaleKeepsWireFailureFastPathWithoutCandidate(t *testing.T) {
	cfg := makeTestConfig()
	cfg.ServeStale = true
	c := New(cfg)
	defer c.Stop()
	e := edns.New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("failure-only.example.", dns.TypeA)
	c.store.RecordFailure(req, netip.Prefix{}, FailureProvenance("test"), nil)
	if !serveFailureThrough(t, c, e, req.Question[0].Name, false) {
		t.Fatal("serve-stale without an answer candidate disabled the cached-failure wire path")
	}
}

func TestServeStalePrecedesWireBornRFC9520FailureHit(t *testing.T) {
	cfg := makeTestConfig()
	cfg.ServeStale = true
	c := New(cfg)
	defer c.Stop()
	e := edns.New(cfg)

	wireReq, req := wireTestRequest(t, "wire-stale.example.", dns.TypeA, false)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.57"), netip.Prefix{}, time.Second, time.Hour)
	c.store.RecordFailure(req, netip.Prefix{}, FailureProvenance("test"), nil)

	beforeFailureWire := wireFailureServed.Value()
	writer := mock.NewWriter("udp", "198.51.100.9:40000")
	terminal := middleware.HandlerFunc(func(_ context.Context, _ *middleware.Chain) {
		t.Fatal("wire-born cached failure reached downstream")
	})
	ch := middleware.NewChain([]middleware.Handler{e, c, terminal})
	ch.ResetWire(writer, wireReq)
	ch.AllowDirectPack()
	ch.Next(context.Background())

	if !writer.Written() || writer.Rcode() != dns.RcodeSuccess {
		t.Fatalf("wire-born stale response = written %v, rcode %s", writer.Written(), dns.RcodeToString[writer.Rcode()])
	}
	if wireFailureServed.Value() != beforeFailureWire {
		t.Fatal("cached SERVFAIL wire path bypassed the stale candidate")
	}
	if ede := dnsutil.GetEDE(writer.Msg()); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer {
		t.Fatalf("wire-born EDE = %+v, want stale answer", ede)
	}
}

func TestServeStalePreservesECSAudience(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("ecs-stale.example.", dns.TypeA)
	req.SetEdns0(1232, false)

	client := netip.MustParsePrefix("203.0.113.128/25")
	scope := netip.MustParsePrefix("203.0.113.0/24")
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.50"), netip.Prefix{}, time.Second, time.Hour)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.51"), scope, time.Second, time.Hour)

	resp, _ := c.staleResponse(req, false, client)
	if resp == nil {
		t.Fatal("scoped stale candidate was not selected")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(netip.MustParseAddr("192.0.2.51").AsSlice()) {
		t.Fatalf("scoped stale answer = %v, want 192.0.2.51", resp.Answer)
	}
}

func TestScopedLookupFreshWiderScopeBeatsExpiredNarrowScope(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("ecs-shadow.example.", dns.TypeA)

	client := netip.MustParsePrefix("203.0.113.130/32")
	narrow := netip.MustParsePrefix("203.0.113.128/26")
	wide := netip.MustParsePrefix("203.0.113.0/24")
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.60"), narrow, time.Second, time.Hour)
	fresh := seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.61"), wide, time.Second, time.Hour)
	fresh.stored = time.Now()

	entry, key, scope := c.scopedLookup(req.Question[0], false, client)
	if entry != fresh || scope != wide {
		t.Fatalf("scoped lookup = (%p, %v), want fresh /24 (%p, %v)", entry, scope, fresh, wide)
	}

	writer := mock.NewWriter("udp", "203.0.113.130:53000")
	ch := middleware.NewChain(nil)
	ch.Reset(writer, req.Copy())
	if !c.handleCacheHit(context.Background(), ch, entry, key, scope, nil) {
		t.Fatal("fresh wider scoped entry was not served as a cache hit")
	}
	if got := answerA(writer.Msg()); got != "192.0.2.61" {
		t.Fatalf("scoped hit answer = %q, want fresh /24 answer 192.0.2.61", got)
	}

	if stale, _ := c.staleResponse(req, false, client); stale != nil {
		t.Fatal("expired /26 was selected although a fresh /24 existed")
	}
}

func TestServeStaleOnClientDeadline(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("deadline.example.", dns.TypeA)
	req.SetEdns0(1232, false)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.52"), netip.Prefix{}, time.Second, time.Hour)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	calls := 0
	resp := runStaleQuery(t, c, req, middleware.HandlerFunc(func(_ context.Context, _ *middleware.Chain) {
		calls++
	}), ctx)
	if calls != 0 {
		t.Fatalf("expired client request reached downstream %d times", calls)
	}
	if resp.Rcode != dns.RcodeSuccess || answerA(resp) != "192.0.2.52" {
		t.Fatalf("deadline response = rcode %s, answer %q; want retained stale answer",
			dns.RcodeToString[resp.Rcode], answerA(resp))
	}
	if ede := dnsutil.GetEDE(resp); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer {
		t.Fatalf("deadline EDE = %+v, want stale-answer", ede)
	}
}

func TestServeStaleOnResolutionFailureAfterDeadline(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("deadline-upstream.example.", dns.TypeA)
	req.SetEdns0(1232, false)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.65"), netip.Prefix{}, time.Second, time.Hour)

	deadlineCtx := &controllableDeadlineContext{Context: context.Background()}
	calls := 0
	resp := runStaleQuery(t, c, req, middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		calls++
		deadlineCtx.expired = true
		failure := new(dns.Msg)
		failure.SetRcode(ch.Request.Msg(), dns.RcodeServerFailure)
		_ = ch.Writer.WriteMsg(failure)
		ch.Cancel()
	}), deadlineCtx)
	if calls != 1 {
		t.Fatalf("downstream calls = %d, want 1", calls)
	}
	if resp.Rcode != dns.RcodeSuccess || answerA(resp) != "192.0.2.65" {
		t.Fatalf("post-deadline response = rcode %s, answer %q; want retained stale answer",
			dns.RcodeToString[resp.Rcode], answerA(resp))
	}
	if ede := dnsutil.GetEDE(resp); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer {
		t.Fatalf("post-deadline EDE = %+v, want stale-answer", ede)
	}
	if hit, ok := c.store.LookupFailure(req, netip.Prefix{}); ok {
		t.Fatalf("request-local deadline published RFC 9520 state: %+v", hit)
	}
}

func TestServeStaleDeadlineWithoutCandidateKeepsLocalFailure(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("deadline-miss.example.", dns.TypeA)
	req.SetEdns0(1232, false)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	calls := 0
	resp := runStaleQuery(t, c, req, middleware.HandlerFunc(func(_ context.Context, _ *middleware.Chain) {
		calls++
	}), ctx)
	if calls != 0 {
		t.Fatalf("expired client request reached downstream %d times", calls)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("deadline response rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if ede := dnsutil.GetEDE(resp); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeNoReachableAuthority {
		t.Fatalf("deadline EDE = %+v, want no-reachable-authority", ede)
	}
}

func TestServeStaleDoesNotOverrideClientCancellation(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("canceled.example.", dns.TypeA)
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.62"), netip.Prefix{}, time.Second, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	ch := middleware.NewChain([]middleware.Handler{c, middleware.HandlerFunc(func(_ context.Context, _ *middleware.Chain) {
		calls++
	})})
	ch.Reset(writer, req)
	ch.Next(ctx)
	if calls != 0 {
		t.Fatalf("canceled client request reached downstream %d times", calls)
	}
	if writer.Written() {
		t.Fatal("transport cancellation wrote a stale response")
	}
}

func TestBoundRequestToStaleLifetime(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		cutUntil  time.Time
		cutKey    uint64
		wantUntil time.Time
		wantKey   uint64
	}{
		{
			name:      "advertised stale lifetime",
			wantUntil: now.Add(staleAnswerTTL),
		},
		{
			name:      "shorter delegation lease",
			cutUntil:  now.Add(5 * time.Second),
			cutKey:    0x8767,
			wantUntil: now.Add(5 * time.Second),
			wantKey:   0x8767,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &CacheEntry{cutUntil: tt.cutUntil, cutKey: tt.cutKey}
			var meta middleware.ResponseMeta
			ctx := middleware.WithResponseMeta(context.Background(), &meta)
			boundRequestToStaleLifetime(ctx, entry, now)
			gotUntil, gotKey := meta.Cut()
			if !gotUntil.Equal(tt.wantUntil) || gotKey != tt.wantKey {
				t.Fatalf("stale bound = (%v, %#x), want (%v, %#x)",
					gotUntil, gotKey, tt.wantUntil, tt.wantKey)
			}
		})
	}
}

func TestServeStaleReadPreservesPrefetchCAS(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := new(dns.Msg)
	req.SetQuestion("refresh.example.", dns.TypeA)
	entry := seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.53"), netip.Prefix{}, time.Second, time.Hour)

	if resp, got := c.staleResponse(req, false, netip.Prefix{}); resp == nil || got != entry {
		t.Fatal("stale read did not return the retained entry")
	}
	key := CacheKey{Question: req.Question[0], CD: false}.Hash()
	if !c.store.ReplaceIfCurrent(
		key,
		entry,
		staleTestAnswer(req, "192.0.2.54"),
		time.Now().Add(time.Hour),
		123,
	) {
		t.Fatal("stale read disturbed ReplaceIfCurrent pointer CAS")
	}
	replacement, ok := c.store.LookupByKeyVerified(key, CacheKey{Question: req.Question[0]})
	if !ok || replacement == entry {
		t.Fatal("successful refresh did not replace the stale entry")
	}
}
