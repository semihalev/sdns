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
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

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
