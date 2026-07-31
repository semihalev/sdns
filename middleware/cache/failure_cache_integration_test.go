package cache

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/internal/waitgroup"
	"github.com/semihalev/sdns/middleware"
)

type failureProbeJoinBarrierWriter struct {
	middleware.ResponseWriter
	reached chan<- struct{}
	release <-chan struct{}
}

func (w *failureProbeJoinBarrierWriter) Internal() bool {
	w.reached <- struct{}{}
	<-w.release
	return false
}

func expireFailureProbeZone(t *testing.T, c *Cache, clock *failureFakeClock) uint64 {
	t.Helper()

	c.failure.now = clock.Now
	c.store.RecordZoneFailure(dns.Question{
		Name:   "seed.dead.example.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, "dead.example.")
	clock.Advance(DefaultFailureInitialTTL + time.Nanosecond)

	req := new(dns.Msg)
	req.SetQuestion("probe.dead.example.", dns.TypeA)
	retryKey, ok := c.store.FailureRetryKey(req, netip.Prefix{})
	if !ok {
		t.Fatal("expired zone failure did not produce a retry key")
	}
	return retryKey
}

func TestFailureCacheFirstResponseThenEDE13Hit(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	var calls atomic.Int32
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		calls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		resp.Rcode = dns.RcodeServerFailure
		resp.AuthenticatedData = true
		resp.SetEdns0(1232, true)
		dnsutil.SetEDE(resp, dns.ExtendedErrorCodeNetworkError, "direct network failure")
		if err := ch.Writer.WriteMsg(resp); err != nil {
			t.Errorf("WriteMsg() error = %v", err)
		}
		ch.Cancel()
	})

	query := func() *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("dead.example.", dns.TypeA)
		req.SetEdns0(1232, true)
		writer := mock.NewWriter("udp", "192.0.2.1:53000")
		ch := middleware.NewChain([]middleware.Handler{c, downstream})
		ch.Reset(writer, req)
		ch.Next(context.Background())
		return writer.Msg()
	}

	first := query()
	if calls.Load() != 1 {
		t.Fatalf("first request downstream calls = %d, want 1", calls.Load())
	}
	firstEDE := dnsutil.GetEDE(first)
	if firstEDE == nil || firstEDE.InfoCode != dns.ExtendedErrorCodeNetworkError {
		t.Fatalf("first response EDE = %+v, want original network error", firstEDE)
	}

	second := query()
	if calls.Load() != 1 {
		t.Fatalf("cached request reached downstream; calls = %d", calls.Load())
	}
	secondEDE := dnsutil.GetEDE(second)
	if secondEDE == nil || secondEDE.InfoCode != dns.ExtendedErrorCodeCachedError {
		t.Fatalf("cached response EDE = %+v, want EDE 13", secondEDE)
	}
	if second.AuthenticatedData {
		t.Fatal("cached failure retained AD")
	}
}

func TestFailureProbeFollowersRegroupAfterRequestLocalLeader(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	clock := newFailureFakeClock()
	expireFailureProbeZone(t, c, clock)

	const requests = 8
	joinReached := make(chan struct{}, requests)
	releaseJoin := make(chan struct{})
	started := make(chan int32, requests)
	releaseFirst := make(chan struct{})
	releaseRemaining := make(chan struct{})
	var releaseJoinOnce, releaseFirstOnce, releaseRemainingOnce sync.Once
	releaseAllJoins := func() {
		releaseJoinOnce.Do(func() { close(releaseJoin) })
	}
	releaseFirstProbe := func() {
		releaseFirstOnce.Do(func() { close(releaseFirst) })
	}
	releaseRemainingProbes := func() {
		releaseRemainingOnce.Do(func() { close(releaseRemaining) })
	}
	t.Cleanup(releaseAllJoins)
	t.Cleanup(releaseFirstProbe)
	t.Cleanup(releaseRemainingProbes)

	var (
		calls       atomic.Int32
		inFlight    atomic.Int32
		maxInFlight atomic.Int32
	)
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		call := calls.Add(1)
		active := inFlight.Add(1)
		for {
			previous := maxInFlight.Load()
			if active <= previous || maxInFlight.CompareAndSwap(previous, active) {
				break
			}
		}
		defer inFlight.Add(-1)

		started <- call
		if call == 1 {
			<-releaseFirst
		} else {
			<-releaseRemaining
		}

		resp := new(dns.Msg)
		resp.SetRcode(ch.Request, dns.RcodeServerFailure)
		middleware.MarkRequestLocalFailureResponse(
			ctx,
			resp,
			middleware.ErrResolutionAttemptLimit,
		)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	results := make(chan *dns.Msg, requests)
	for i := range requests {
		req := new(dns.Msg)
		req.SetQuestion(string(rune('a'+i))+".dead.example.", dns.TypeA)
		req.SetEdns0(dnsutil.DefaultMsgSize, true)

		writer := mock.NewWriter("udp", "192.0.2.1:53000")
		chain := middleware.NewChain([]middleware.Handler{c, downstream})
		chain.Reset(writer, req)
		chain.Writer = &failureProbeJoinBarrierWriter{
			ResponseWriter: chain.Writer,
			reached:        joinReached,
			release:        releaseJoin,
		}

		go func() {
			chain.Next(context.Background())
			results <- writer.Msg()
		}()
	}

	for range requests {
		select {
		case <-joinReached:
		case <-time.After(time.Second):
			t.Fatal("request did not reach the initial failure-probe election")
		}
	}
	releaseAllJoins()

	select {
	case call := <-started:
		if call != 1 {
			t.Fatalf("first downstream call number = %d, want 1", call)
		}
	case <-time.After(time.Second):
		t.Fatal("initial failure probe did not reach downstream")
	}

	// Every request was released immediately before Join. Keep the first
	// leader blocked long enough for all seven distinct-QNAME followers to
	// attach to its generation before returning a request-local failure.
	time.Sleep(50 * time.Millisecond)
	releaseFirstProbe()

	select {
	case call := <-started:
		if call != 2 {
			t.Fatalf("regrouped downstream call number = %d, want 2", call)
		}
	case <-time.After(time.Second):
		t.Fatal("no follower became the next failure-probe leader")
	}

	select {
	case call := <-started:
		t.Fatalf("failure-probe followers fanned out; concurrent call %d reached downstream", call)
	case <-time.After(100 * time.Millisecond):
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("downstream calls while regrouped leader blocked = %d, want 2", got)
	}
	if got := inFlight.Load(); got != 1 {
		t.Fatalf("in-flight regrouped probes = %d, want 1", got)
	}

	releaseRemainingProbes()
	for i := range requests {
		select {
		case msg := <-results:
			if msg == nil || msg.Rcode != dns.RcodeServerFailure {
				t.Fatalf("result %d = %#v, want request-local SERVFAIL", i, msg)
			}
		case <-time.After(time.Second):
			t.Fatalf("request %d did not finish after releasing regrouped probes", i)
		}
	}
	if got := calls.Load(); got != requests {
		t.Fatalf("eventual downstream calls = %d, want %d sequential local attempts", got, requests)
	}
	if got := maxInFlight.Load(); got != 1 {
		t.Fatalf("maximum concurrent failure probes = %d, want 1", got)
	}
}

func TestFailureProbeRegroupDoesNotSpinOnExpiredWaitGeneration(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	clock := newFailureFakeClock()
	retryKey := expireFailureProbeZone(t, c, clock)
	c.wg = waitgroup.New(20 * time.Millisecond)
	if wait := c.wg.Join(retryKey); wait != nil {
		t.Fatal("failed to install abandoned failure-probe leader")
	}
	defer c.wg.Done(retryKey)

	var calls atomic.Int32
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		calls.Add(1)
		resp := new(dns.Msg)
		resp.SetRcode(ch.Request, dns.RcodeServerFailure)
		middleware.MarkRequestLocalFailureResponse(
			ctx,
			resp,
			middleware.ErrResolutionAttemptLimit,
		)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	req := new(dns.Msg)
	req.SetQuestion("timeout.dead.example.", dns.TypeA)
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	chain := middleware.NewChain([]middleware.Handler{c, downstream})
	chain.Reset(writer, req)

	done := make(chan struct{})
	go func() {
		chain.Next(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("follower spun while rejoining an already-expired wait generation")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("timeout fall-through downstream calls = %d, want 1", got)
	}
}

func TestFailureProbeCanceledFollowerStopsBeforeRegroup(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	clock := newFailureFakeClock()
	retryKey := expireFailureProbeZone(t, c, clock)
	if wait := c.wg.Join(retryKey); wait != nil {
		t.Fatal("failed to install failure-probe leader")
	}
	defer c.wg.Done(retryKey)

	var calls atomic.Int32
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		calls.Add(1)
		ch.Cancel()
	})

	req := new(dns.Msg)
	req.SetQuestion("canceled.dead.example.", dns.TypeA)
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	chain := middleware.NewChain([]middleware.Handler{c, downstream})
	chain.Reset(writer, req)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	chain.Next(ctx)

	if got := calls.Load(); got != 0 {
		t.Fatalf("canceled follower reached downstream %d times, want 0", got)
	}
	if writer.Written() {
		t.Fatalf("canceled follower wrote an unexpected response: %#v", writer.Msg())
	}
}

func TestFailureCacheZoneSuppressesRandomQName(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	c.store.RecordZoneFailure(dns.Question{
		Name:   "seed.dead.example.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, "dead.example.")

	var calls atomic.Int32
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		calls.Add(1)
		ch.CancelWithRcode(dns.RcodeServerFailure, true)
	})

	for _, name := range []string{"one.dead.example.", "two.dead.example.", "dead.example."} {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeAAAA)
		req.SetEdns0(1232, true)
		writer := mock.NewWriter("udp", "192.0.2.1:53000")
		ch := middleware.NewChain([]middleware.Handler{c, downstream})
		ch.Reset(writer, req)
		ch.Next(context.Background())

		if ede := dnsutil.GetEDE(writer.Msg()); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeCachedError {
			t.Fatalf("%s EDE = %+v, want cached error", name, ede)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("zone failure leaked %d random-QNAME requests downstream", calls.Load())
	}
}

func TestFailureCacheZoneRecoveryRequiresFinalPipelineEvidence(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	q := dns.Question{Name: "www.dead.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.store.RecordZoneFailure(q, "dead.example.")

	// A useful local/static response may be cached under the same name, but it
	// says nothing about authority reachability and must not clear zone state.
	local := new(dns.Msg)
	local.SetQuestion(q.Name, q.Qtype)
	local.Response = true
	local.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 10},
	}}
	c.store.SetFromResponse(local, false, time.Time{})

	probe := new(dns.Msg)
	probe.SetQuestion("other.dead.example.", dns.TypeAAAA)
	if _, ok := c.store.LookupFailure(probe, netip.Prefix{}); !ok {
		t.Fatal("local success incorrectly cleared authority failure state")
	}

	// A useful response reaching the cache's outer response writer is final
	// pipeline evidence: a resolver, forwarder, or failover path recovered.
	// It clears both this exact question and the covering failed-zone state.
	req := new(dns.Msg)
	req.SetQuestion(q.Name, q.Qtype)
	recovered := new(dns.Msg)
	recovered.SetReply(req)
	recovered.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 11},
	}}
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	rw := &ResponseWriter{
		ResponseWriter: writer,
		cache:          c,
		ctx:            context.Background(),
		req:            req,
	}
	if err := rw.WriteMsg(recovered); err != nil {
		t.Fatalf("WriteMsg() recovery evidence: %v", err)
	}

	if hit, ok := c.store.LookupFailure(probe, netip.Prefix{}); ok {
		t.Fatalf("final pipeline recovery evidence did not clear zone state: %#v", hit)
	}
}

func TestFailureCacheScopedSuccessDoesNotResetGlobalAudience(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("geo.example.", dns.TypeA)
	c.store.RecordFailure(req, netip.Prefix{}, FailureProvenance("global"))

	scope := netip.MustParsePrefix("192.0.2.0/24")
	scoped := new(dns.Msg)
	scoped.SetReply(req)
	scoped.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 20},
	}}
	scopedKey := CacheKey{Question: req.Question[0], Scope: scope}.Hash()
	c.store.SetFromResponseScoped(scopedKey, scoped, time.Time{}, 0)

	if hit, ok := c.store.LookupFailure(req, netip.Prefix{}); !ok || hit.Provenance != "global" {
		t.Fatalf("scoped success reset global failure audience: %#v, %v", hit, ok)
	}
}
