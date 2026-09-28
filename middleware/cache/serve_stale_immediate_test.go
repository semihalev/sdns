package cache

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// immediateCache is a cache in serve_stale_mode "immediate" whose refreshes
// answer with refresh and are counted in refreshes; done receives once per
// completed refresh.
func immediateCache(t *testing.T, cfg *config.Config, refresh func(req *dns.Msg) *dns.Msg) (*Cache, *atomic.Int32, chan struct{}) {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.CacheSize = 1024
	cfg.ServeStale = true
	cfg.ServeStaleMode = "immediate"
	c := New(cfg)
	t.Cleanup(c.Stop)
	var refreshes atomic.Int32
	done := make(chan struct{}, 16)
	c.SetPrefetchQueryer(queryerFunc(func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		refreshes.Add(1)
		defer func() { done <- struct{}{} }()
		return refresh(req), nil
	}))
	return c, &refreshes, done
}

func immediateQuery(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(1232, true)
	return req
}

// resolveHandler stands in for the resolver: counted, answering fresh.
func resolveHandler(calls *int, address string) middleware.Handler {
	return middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		(*calls)++
		_ = ch.Writer.WriteMsg(staleTestAnswer(ch.Request.Msg(), address))
		ch.Cancel()
	})
}

func waitRefresh(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no refresh ran")
	}
	// The write-back follows the queryer's return.
	time.Sleep(50 * time.Millisecond)
}

func answerAddress(t *testing.T, resp *dns.Msg) string {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("response rcode %s with %d answers, want one A", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	return resp.Answer[0].(*dns.A).A.String()
}

// An expired entry answers at once, as a stale answer (TTL 30, EDE 3),
// without waiting on resolution; the refresh it starts puts the fresh answer
// in the cache for the next query.
func TestServeStaleImmediateAnswersAndRefreshes(t *testing.T) {
	c, refreshes, done := immediateCache(t, nil, func(req *dns.Msg) *dns.Msg { return staleTestAnswer(req, "192.0.2.2") })
	req := immediateQuery("swr.example.")
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)

	calls := 0
	resp := runStaleQuery(t, c, req.Copy(), resolveHandler(&calls, "192.0.2.3"), context.Background())
	if calls != 0 {
		t.Fatalf("resolution ran %d times, want the stale answer at once", calls)
	}
	if got := answerAddress(t, resp); got != "192.0.2.1" || resp.Answer[0].Header().Ttl != 30 {
		t.Fatalf("answer %s TTL %d, want the stale 192.0.2.1 at TTL 30", got, resp.Answer[0].Header().Ttl)
	}
	if ede := dnsutil.GetEDE(resp); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer {
		t.Fatalf("EDE %+v, want Stale Answer", ede)
	}

	waitRefresh(t, done)
	resp = runStaleQuery(t, c, req.Copy(), resolveHandler(&calls, "192.0.2.3"), context.Background())
	if got := answerAddress(t, resp); got != "192.0.2.2" || calls != 0 || refreshes.Load() != 1 {
		t.Fatalf("after the refresh: answer %s, %d resolutions, %d refreshes; want the refreshed 192.0.2.2 from the cache",
			got, calls, refreshes.Load())
	}
}

// The default mode waits on resolution, and serves stale only after it fails.
func TestServeStaleFailureModeResolvesFirst(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, ServeStale: true})
	defer c.Stop()
	req := immediateQuery("failure-mode.example.")
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)

	calls := 0
	resp := runStaleQuery(t, c, req, resolveHandler(&calls, "192.0.2.3"), context.Background())
	if got := answerAddress(t, resp); got != "192.0.2.3" || calls != 1 {
		t.Fatalf("answer %s after %d resolutions, want the resolved 192.0.2.3", got, calls)
	}
}

// Everything that keeps the failure path from serving an entry keeps this
// path from serving it too, and so does anything it cannot answer without
// work: each of these is left to resolution, and starts no refresh.
func TestServeStaleImmediateDeclines(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   *config.Config
		seed  func(t *testing.T, c *Cache, req *dns.Msg)
		shape func(req *dns.Msg)
		setup func(c *Cache)
	}{
		{name: "an expired delegation lease", seed: func(t *testing.T, c *Cache, req *dns.Msg) {
			seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, -time.Second)
		}},
		{name: "past serve_stale_max_ttl", cfg: func() *config.Config {
			cfg := &config.Config{}
			cfg.ServeStaleMaxTTL.Duration = time.Minute
			return cfg
		}(), seed: func(t *testing.T, c *Cache, req *dns.Msg) {
			seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, 2*time.Minute, time.Hour)
		}},
		{name: "an alias the entry cannot complete", seed: func(t *testing.T, c *Cache, req *dns.Msg) {
			alias := new(dns.Msg)
			alias.SetReply(req)
			alias.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "target.example.",
			}}
			seedStaleEntry(t, c, alias, netip.Prefix{}, time.Second, time.Hour)
		}},
		{name: "signatures that lapsed while it was stale", seed: func(t *testing.T, c *Cache, req *dns.Msg) {
			// Admission drops a lapsed signature, so the one stored is
			// current then and lapses a second later.
			answer := staleTestAnswer(req, "192.0.2.1")
			answer.Answer = append(answer.Answer, &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, Labels: 2, OrigTtl: 300,
				Expiration: uint32(time.Now().Add(time.Second).Unix()), //nolint:gosec // test fixture
				Inception:  uint32(time.Now().Add(-time.Hour).Unix()),  //nolint:gosec // test fixture
				KeyTag:     1, SignerName: "example.", Signature: "AAAA",
			})
			seedStaleEntry(t, c, answer, netip.Prefix{}, time.Second, time.Hour)
			time.Sleep(2 * time.Second)
		}},
		{name: "a question that does not desire recursion", seed: func(t *testing.T, c *Cache, req *dns.Msg) {
			seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)
		}, shape: func(req *dns.Msg) { req.RecursionDesired = false }},
		{name: "a refresh that cannot be queued", seed: func(t *testing.T, c *Cache, req *dns.Msg) {
			seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)
		}, setup: func(c *Cache) { c.prefetchQueue.Stop() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, refreshes, _ := immediateCache(t, tc.cfg, func(req *dns.Msg) *dns.Msg { return staleTestAnswer(req, "192.0.2.2") })
			req := immediateQuery("decline.example.")
			tc.seed(t, c, req)
			if tc.shape != nil {
				tc.shape(req)
			}
			if tc.setup != nil {
				tc.setup(c)
			}
			calls := 0
			w := runStaleQueryWriter(c, req, resolveHandler(&calls, "192.0.2.3"), context.Background())
			if w.Written() && dnsutil.GetEDE(w.Msg()) != nil && dnsutil.GetEDE(w.Msg()).InfoCode == dns.ExtendedErrorCodeStaleAnswer {
				t.Fatal("served stale")
			}
			time.Sleep(50 * time.Millisecond)
			if n := refreshes.Load(); n != 0 {
				t.Fatalf("%d refreshes started, want none", n)
			}
			if req.RecursionDesired && calls != 1 {
				t.Fatalf("resolution ran %d times, want the question resolved", calls)
			}
		})
	}
}

// A refresh already under way is enough: the entry answers stale and no
// second refresh starts.
func TestServeStaleImmediateJoinsARefreshUnderWay(t *testing.T) {
	c, refreshes, _ := immediateCache(t, nil, func(req *dns.Msg) *dns.Msg { return staleTestAnswer(req, "192.0.2.2") })
	req := immediateQuery("inflight.example.")
	entry := seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)
	entry.prefetch.Store(true)

	calls := 0
	resp := runStaleQuery(t, c, req, resolveHandler(&calls, "192.0.2.3"), context.Background())
	if got := answerAddress(t, resp); got != "192.0.2.1" || calls != 0 {
		t.Fatalf("answer %s after %d resolutions, want the stale 192.0.2.1 at once", got, calls)
	}
	time.Sleep(50 * time.Millisecond)
	if n := refreshes.Load(); n != 0 {
		t.Fatalf("%d refreshes started beside the one under way", n)
	}
}

// A refresh that fails is recorded as a resolution failure (RFC 9520): the
// next queries meet the failure rung, which answers from the entry stale,
// and no further refresh starts until the failure expires.
func TestServeStaleImmediateBacksOffAfterAFailedRefresh(t *testing.T) {
	c, refreshes, done := immediateCache(t, nil, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		return resp
	})
	req := immediateQuery("failing.example.")
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)

	calls := 0
	if got := answerAddress(t, runStaleQuery(t, c, req.Copy(), resolveHandler(&calls, "192.0.2.3"), context.Background())); got != "192.0.2.1" {
		t.Fatalf("first answer %s, want the stale 192.0.2.1", got)
	}
	waitRefresh(t, done)
	for i := range 3 {
		resp := runStaleQuery(t, c, req.Copy(), resolveHandler(&calls, "192.0.2.3"), context.Background())
		if got := answerAddress(t, resp); got != "192.0.2.1" {
			t.Fatalf("query %d after the failed refresh: answer %s, want the stale 192.0.2.1", i, got)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := refreshes.Load(); n != 1 || calls != 0 {
		t.Fatalf("%d refreshes and %d resolutions after a failed refresh, want 1 and 0", n, calls)
	}
}

// A refresh the validator rejected is recorded as a validation failure, as
// on the client path, so nothing may route around it; an ordinary failure
// stays an ordinary one.
func TestServeStaleImmediateFailedRefreshKeepsItsProvenance(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bogus bool
		want  FailureProvenance
	}{
		{"a bogus answer", true, FailureProvenanceValidation},
		{"an unreachable authority", false, FailureProvenance("response")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, ServeStale: true, ServeStaleMode: "immediate"})
			t.Cleanup(c.Stop)
			done := make(chan struct{}, 1)
			c.SetPrefetchQueryer(queryerFunc(func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
				defer func() { done <- struct{}{} }()
				resp := new(dns.Msg)
				resp.SetRcode(req, dns.RcodeServerFailure)
				if tc.bogus {
					middleware.MarkValidationFailureResponse(ctx, resp)
				}
				return resp, nil
			}))
			req := immediateQuery("provenance.example.")
			seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)

			calls := 0
			runStaleQuery(t, c, req.Copy(), resolveHandler(&calls, "192.0.2.3"), context.Background())
			waitRefresh(t, done)
			hit, ok := c.lookupFailure(req, netip.Prefix{})
			if !ok || hit.Provenance != tc.want {
				t.Fatalf("recorded failure %+v (found %v), want provenance %q", hit, ok, tc.want)
			}
		})
	}
}

// A refresh that answers NOERROR or NXDOMAIN refreshes the data even when it
// cannot be stored (RFC 8767 §4): an NXDOMAIN with a zero negative TTL
// retires the expired entry, and the next query is resolved rather than
// served the withdrawn address again.
func TestServeStaleImmediateUncacheableRefreshRetiresTheEntry(t *testing.T) {
	c, refreshes, done := immediateCache(t, nil, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeNameError)
		resp.Ns = []dns.RR{&dns.SOA{
			Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
			Ns:  "ns.example.", Mbox: "host.example.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 0,
		}}
		return resp
	})
	req := immediateQuery("withdrawn.example.")
	seedStaleEntry(t, c, staleTestAnswer(req, "192.0.2.1"), netip.Prefix{}, time.Second, time.Hour)

	calls := 0
	if got := answerAddress(t, runStaleQuery(t, c, req.Copy(), resolveHandler(&calls, "192.0.2.3"), context.Background())); got != "192.0.2.1" {
		t.Fatalf("first answer %s, want the stale 192.0.2.1", got)
	}
	waitRefresh(t, done)
	resp := runStaleQuery(t, c, req.Copy(), resolveHandler(&calls, "192.0.2.3"), context.Background())
	if calls != 1 || answerAddress(t, resp) != "192.0.2.3" {
		t.Fatalf("after the withdrawal: %d resolutions, answer %v; want the question resolved", calls, resp.Answer)
	}
	if n := refreshes.Load(); n != 1 {
		t.Fatalf("%d refreshes, want 1", n)
	}
}
