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
)

func TestRFC9520KillSwitchDisablesFailureState(t *testing.T) {
	disabled := false

	t.Run("question and zone admission are no-ops", func(t *testing.T) {
		c := New(&config.Config{
			CacheSize: 1024,
			Expire:    300,
			RFC9520:   &disabled,
		})
		defer c.Stop()

		req := new(dns.Msg)
		req.SetQuestion("failed.example.", dns.TypeA)
		failure := new(dns.Msg)
		failure.SetRcode(req, dns.RcodeServerFailure)

		c.Set(CacheKey{Question: req.Question[0]}.Hash(), failure)
		c.store.RecordFailure(req, netip.Prefix{}, FailureProvenance("test"), nil)
		c.store.RecordZoneFailure(req.Question[0], "example.")

		if got := c.failure.Len(); got != 0 {
			t.Fatalf("disabled RFC 9520 admitted %d lower-level failure entries", got)
		}
		if hit, ok := c.store.LookupFailure(req, netip.Prefix{}); ok {
			t.Fatalf("disabled RFC 9520 returned question failure %#v", hit)
		}

		descendant := new(dns.Msg)
		descendant.SetQuestion("other.example.", dns.TypeAAAA)
		if hit, ok := c.store.LookupFailure(descendant, netip.Prefix{}); ok {
			t.Fatalf("disabled RFC 9520 returned zone failure %#v", hit)
		}
		if _, ok := c.store.FailureRetryKey(descendant, netip.Prefix{}); ok {
			t.Fatal("disabled RFC 9520 returned a retry generation")
		}
		assertDisabledFailureSizes(t, c)
	})

	t.Run("lookup ignores retained lower-level state", func(t *testing.T) {
		c := New(&config.Config{
			CacheSize: 1024,
			Expire:    300,
			RFC9520:   &disabled,
		})
		defer c.Stop()

		clock := newFailureFakeClock()
		c.failure.now = clock.Now

		req := new(dns.Msg)
		req.SetQuestion("planted.example.", dns.TypeA)
		c.failure.RecordQuestion(FailureQuestionKey{
			Question: req.Question[0],
		}, FailureProvenance("planted"), nil)
		c.failure.RecordZone(FailureZoneKey{
			Zone:   "example.",
			Qclass: dns.ClassINET,
		}, FailureProvenance("planted"), nil)
		if got := c.failure.Len(); got != 2 {
			t.Fatalf("lower-level planted failure entries = %d, want 2", got)
		}

		if hit, ok := c.store.LookupFailure(req, netip.Prefix{}); ok {
			t.Fatalf("disabled RFC 9520 exposed planted failure %#v", hit)
		}
		clock.Advance(DefaultFailureInitialTTL + time.Nanosecond)
		if _, ok := c.store.FailureRetryKey(req, netip.Prefix{}); ok {
			t.Fatal("disabled RFC 9520 exposed planted retry history")
		}
		assertDisabledFailureSizes(t, c)
	})
}

func TestRFC9520KillSwitchLeavesOrdinaryAndRFC8020CachingEnabled(t *testing.T) {
	disabled := false
	c := New(&config.Config{
		CacheSize: 1024,
		Expire:    300,
		DNSSEC:    "on",
		RFC9520:   &disabled,
	})
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("ordinary.example.", dns.TypeA)
	answer := new(dns.Msg)
	answer.SetReply(req)
	answer.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: []byte{192, 0, 2, 10},
	}}
	c.store.SetFromResponse(answer, false, time.Time{})

	got, ok := c.store.GetWithContext(context.Background(), req)
	if !ok || got == nil || len(got.Answer) != 1 || got.Rcode != dns.RcodeSuccess {
		t.Fatalf("ordinary cache with RFC 9520 disabled = %#v, hit=%v", got, ok)
	}

	fixture := newNXDomainCutFixture(t, "missing.example.", "example.", dns.ClassINET)
	if !c.store.RecordNXDomainCut(
		fixture.msg,
		"missing.example.",
		"example.",
		time.Time{},
	) {
		t.Fatal("RFC 9520 kill switch unexpectedly disabled RFC 8020 admission")
	}

	cutReq := new(dns.Msg)
	cutReq.SetQuestion("child.missing.example.", dns.TypeAAAA)
	got, ok = c.store.GetWithContext(context.Background(), cutReq)
	if !ok || got == nil || got.Rcode != dns.RcodeNameError {
		t.Fatalf("RFC 8020 lookup with RFC 9520 disabled = %#v, hit=%v", got, ok)
	}
	assertDisabledFailureSizes(t, c)
}

func TestRFC9520KillSwitchDoesNotShareSERVFAILBetweenRequests(t *testing.T) {
	disabled := false
	c := New(&config.Config{
		CacheSize: 1024,
		Expire:    300,
		RFC9520:   &disabled,
	})
	defer c.Stop()

	calls := 0
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		calls++
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Rcode = dns.RcodeServerFailure
		resp.SetEdns0(dnsutil.DefaultMsgSize, false)
		dnsutil.SetEDE(resp, dns.ExtendedErrorCodeNetworkError, "upstream failure")
		if err := ch.Writer.WriteMsg(resp); err != nil {
			t.Errorf("WriteMsg() error = %v", err)
		}
		ch.Cancel()
	})

	query := func() *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("failed.example.", dns.TypeA)
		req.SetEdns0(dnsutil.DefaultMsgSize, true)
		writer := mock.NewWriter("udp", "192.0.2.1:53000")
		chain := middleware.NewChain([]middleware.Handler{c, downstream})
		chain.Reset(writer, req)
		chain.Next(context.Background())
		return writer.Msg()
	}

	for request := 1; request <= 2; request++ {
		resp := query()
		if resp == nil || resp.Rcode != dns.RcodeServerFailure {
			t.Fatalf("request %d response = %#v, want SERVFAIL", request, resp)
		}
		ede := dnsutil.GetEDE(resp)
		if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeNetworkError {
			t.Fatalf("request %d EDE = %#v, want original network error", request, ede)
		}
	}
	if calls != 2 {
		t.Fatalf("two independent requests reached downstream %d times, want 2", calls)
	}
	assertDisabledFailureSizes(t, c)
}

func assertDisabledFailureSizes(t *testing.T, c *Cache) {
	t.Helper()

	if got := c.store.FailureLen(); got != 0 {
		t.Fatalf("disabled RFC 9520 Store.FailureLen() = %d, want 0", got)
	}
	stats := c.Stats()
	got, ok := stats["failure_size"].(int)
	if !ok {
		t.Fatalf("failure_size statistic has type %T, want int", stats["failure_size"])
	}
	if got != 0 {
		t.Fatalf("disabled RFC 9520 failure_size = %d, want 0", got)
	}
}
