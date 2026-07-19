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
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

var _ middleware.CutStore = (*Store)(nil)

func cutTestMsg(name string, rcode int, answerTTL uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Rcode = rcode
	m.Response = true
	if rcode == dns.RcodeSuccess {
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL},
			A:   []byte{192, 0, 2, 1},
		}}
	}
	return m
}

func cutTestNXMsg(name string, ttl uint32) *dns.Msg {
	m := cutTestMsg(name, dns.RcodeNameError, 0)
	m.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 60,
		Retry:   60,
		Expire:  60,
		Minttl:  ttl,
	}}
	return m
}

type cutTestQueryer struct {
	handlers []middleware.Handler
}

func (q *cutTestQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain(q.handlers)
	ch.Reset(w, req)
	ch.Next(ctx)
	if !w.Written() {
		return nil, middleware.ErrNoResponse
	}
	return w.Msg(), nil
}

// TestCacheEntry_CutUntil locks in the effective-lifetime math for the
// answer-cache ghost fix (GHSA-mqfw-f48p-2vc8): an entry's lifetime is
// min(stored+ttl, cutUntil), enforced at read time.
func TestCacheEntry_CutUntil(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	// Cut shorter than the TTL: the cut wins.
	e := NewCacheEntry(cutTestMsg("example.org.", dns.RcodeSuccess, 300), 300*time.Second, 0)
	e.cutUntil = time.Now().Add(2 * time.Second)

	if e.IsExpired() {
		t.Fatal("entry must be valid before its cut deadline")
	}
	if ttl := e.TTL(); ttl > 2 {
		t.Fatalf("TTL() = %d, must be capped by the 2s cut, not the 300s TTL", ttl)
	}
	msg := e.ToMsg(req)
	if msg == nil {
		t.Fatal("ToMsg must materialise before the cut deadline")
	}
	if got := msg.Answer[0].Header().Ttl; got > 2 {
		t.Fatalf("served TTL = %d, must be capped by the 2s cut", got)
	}

	// Past the cut: expired despite ~300s of TTL remaining.
	e.cutUntil = time.Now().Add(-time.Millisecond)
	if !e.IsExpired() {
		t.Fatal("entry must expire at its cut deadline even with TTL remaining")
	}
	if e.ToMsg(req) != nil {
		t.Fatal("ToMsg must refuse to serve past the cut deadline")
	}
	if e.TTL() != 0 {
		t.Fatal("TTL() must be 0 past the cut deadline")
	}

	// Zero cut: plain TTL behaviour unchanged.
	e.cutUntil = time.Time{}
	if e.IsExpired() || e.TTL() == 0 || e.ToMsg(req) == nil {
		t.Fatal("zero cutUntil must leave plain TTL behaviour unchanged")
	}

	// Cut longer than the TTL: the TTL wins.
	short := NewCacheEntry(cutTestMsg("example.org.", dns.RcodeSuccess, 1), time.Second, 0)
	short.cutUntil = time.Now().Add(time.Hour)
	if ttl := short.TTL(); ttl > 1 {
		t.Fatalf("TTL() = %d, a long cut must not extend a short TTL", ttl)
	}
}

// TestStore_CutUntil_OverridesMinTTLFloor: the configured MinTTL floor
// (5s) inflates stored TTLs, which is exactly how a ghost answer under
// a short cut would outlive its delegation. The cut bound is enforced
// at read time, so it wins over the floor.
func TestStore_CutUntil_OverridesMinTTLFloor(t *testing.T) {
	s := NewStore(
		NewPositiveCache(1024, minTTL, maxTTL, &CacheMetrics{}),
		NewNegativeCache(1024, minTTL, time.Hour, &CacheMetrics{}),
		CacheConfig{},
	)

	resp := cutTestMsg("ghost.example.", dns.RcodeSuccess, 1)
	key := CacheKey{Question: resp.Question[0], CD: false}.Hash()

	// A cut already in the past: the entry may be stored, but must
	// never be served — even though the MinTTL floor lifted its TTL
	// to 5s.
	s.SetFromResponseWithKey(key, resp, time.Now().Add(-time.Millisecond), 0)

	req := new(dns.Msg)
	req.SetQuestion("ghost.example.", dns.TypeA)
	if _, ok := s.Get(req); ok {
		t.Fatal("answer served past its delegation cut (MinTTL floor overrode the cut)")
	}

	// A future cut inside the floor: served, but with the cut-capped TTL.
	s.SetFromResponseWithKey(key, resp, time.Now().Add(2*time.Second), 0)
	msg, ok := s.Get(req)
	if !ok {
		t.Fatal("entry with a future cut must be served")
	}
	if got := msg.Answer[0].Header().Ttl; got > 2 {
		t.Fatalf("served TTL = %d, must be capped by the 2s cut despite the 5s MinTTL floor", got)
	}
}

func TestStore_CutUntil_CoversNegativeCDAndECS(t *testing.T) {
	s := NewStore(
		NewPositiveCache(1024, minTTL, maxTTL, &CacheMetrics{}),
		NewNegativeCache(1024, minTTL, time.Hour, &CacheMetrics{}),
		CacheConfig{},
	)

	t.Run("negative answer", func(t *testing.T) {
		const cutKey = uint64(0x101)
		resp := cutTestNXMsg("missing.example.", 300)
		key := CacheKey{Question: resp.Question[0], CD: false}.Hash()
		cut := time.Now().Add(2 * time.Second)
		s.SetFromResponseWithKey(key, resp, cut, cutKey)

		entry, ok := s.LookupByKey(key)
		if !ok {
			t.Fatal("negative answer was not cached")
		}
		if !entry.cutUntil.Equal(cut) || entry.cutKey != cutKey {
			t.Fatalf("negative cut = (%v, %#x), want (%v, %#x)", entry.cutUntil, entry.cutKey, cut, cutKey)
		}

		s.SetFromResponseWithKey(key, resp, time.Now().Add(-time.Millisecond), cutKey)
		if _, ok := s.LookupByKey(key); ok {
			t.Fatal("negative answer survived past its delegation cut")
		}
	})

	t.Run("CD buckets", func(t *testing.T) {
		resp := cutTestMsg("cd.example.", dns.RcodeSuccess, 300)
		falseCut, trueCut := time.Now().Add(time.Minute), time.Now().Add(2*time.Minute)
		const falseKey, trueKey = uint64(0x201), uint64(0x202)
		s.SetFromResponseWithCut(resp, false, falseCut, falseKey)
		s.SetFromResponseWithCut(resp, true, trueCut, trueKey)

		for _, tc := range []struct {
			cd       bool
			deadline time.Time
			cutKey   uint64
		}{{false, falseCut, falseKey}, {true, trueCut, trueKey}} {
			req := new(dns.Msg)
			req.SetQuestion("cd.example.", dns.TypeA)
			req.CheckingDisabled = tc.cd
			entry, ok := s.Lookup(req)
			if !ok {
				t.Fatalf("CD=%v entry missing", tc.cd)
			}
			if !entry.cutUntil.Equal(tc.deadline) || entry.cutKey != tc.cutKey {
				t.Fatalf("CD=%v cut = (%v, %#x), want (%v, %#x)", tc.cd, entry.cutUntil, entry.cutKey, tc.deadline, tc.cutKey)
			}
		}
	})

	t.Run("ECS scoped", func(t *testing.T) {
		resp := cutTestMsg("ecs.example.", dns.RcodeSuccess, 300)
		key := CacheKey{Question: resp.Question[0], CD: false, Scope: netip.MustParsePrefix("192.0.2.0/24")}.Hash()
		cut := time.Now().Add(2 * time.Second)
		const cutKey = uint64(0x301)
		s.SetFromResponseScoped(key, resp, cut, cutKey)
		entry, ok := s.LookupByKey(key)
		if !ok {
			t.Fatal("ECS-scoped entry missing")
		}
		if !entry.cutUntil.Equal(cut) || entry.cutKey != cutKey {
			t.Fatalf("ECS cut = (%v, %#x), want (%v, %#x)", entry.cutUntil, entry.cutKey, cut, cutKey)
		}
		s.SetFromResponseScoped(key, resp, time.Now().Add(-time.Millisecond), cutKey)
		if _, ok := s.LookupByKey(key); ok {
			t.Fatal("ECS-scoped entry survived past its delegation cut")
		}
	})
}

// TestStore_ReplaceIfCurrent locks in the pointer-CAS late-write
// semantics (GHSA-mqfw-f48p-2vc8, late prefetch overwrite): a refresh
// may only replace the exact entry it captured, and a SERVFAIL refresh
// may never displace a positive entry.
func TestStore_ReplaceIfCurrent(t *testing.T) {
	s := NewStore(
		NewPositiveCache(1024, minTTL, maxTTL, &CacheMetrics{}),
		NewNegativeCache(1024, minTTL, time.Hour, &CacheMetrics{}),
		CacheConfig{},
	)

	q := dns.Question{Name: "cas.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := CacheKey{Question: q, CD: false}.Hash()

	s.SetFromResponseWithKey(key, cutTestMsg("cas.example.", dns.RcodeSuccess, 60), time.Time{}, 0)
	claimed, ok := s.LookupByKey(key)
	if !ok {
		t.Fatal("seed entry missing")
	}

	// Nil expected never stores.
	if s.ReplaceIfCurrent(key, nil, cutTestMsg("cas.example.", dns.RcodeSuccess, 60), time.Time{}, 0) {
		t.Fatal("ReplaceIfCurrent with nil expected must be a no-op")
	}

	// Current entry matches: refresh lands.
	if !s.ReplaceIfCurrent(key, claimed, cutTestMsg("cas.example.", dns.RcodeSuccess, 120), time.Time{}, 0) {
		t.Fatal("refresh of the still-current entry must succeed")
	}
	replaced, _ := s.LookupByKey(key)
	if replaced == claimed {
		t.Fatal("entry was not replaced")
	}

	// Stale expected (the entry it captured is gone): refresh dropped.
	// This is the late-prefetch-overwrite guard — `claimed` plays the
	// role of the entry a slow prefetch captured before newer state
	// (here `replaced`, in reality a withdrawal NXDOMAIN) landed.
	if s.ReplaceIfCurrent(key, claimed, cutTestMsg("cas.example.", dns.RcodeSuccess, 60), time.Time{}, 0) {
		t.Fatal("a stale refresh must not overwrite newer state")
	}
	if cur, _ := s.LookupByKey(key); cur != replaced {
		t.Fatal("newer entry was clobbered by the stale refresh")
	}

	// SERVFAIL refresh never displaces a positive entry.
	if s.ReplaceIfCurrent(key, replaced, cutTestMsg("cas.example.", dns.RcodeServerFailure, 0), time.Time{}, 0) {
		t.Fatal("a SERVFAIL refresh must never displace a positive entry")
	}
	if _, ok := s.LookupByKey(key); !ok {
		t.Fatal("positive entry lost after SERVFAIL refresh attempt")
	}

	// SERVFAIL-to-SERVFAIL refresh within the negative cache works.
	negQ := dns.Question{Name: "neg.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	negKey := CacheKey{Question: negQ, CD: false}.Hash()
	s.SetFromResponseWithKey(negKey, cutTestMsg("neg.example.", dns.RcodeServerFailure, 0), time.Time{}, 0)
	negEntry, ok := s.LookupByKey(negKey)
	if !ok {
		t.Fatal("negative seed entry missing")
	}
	if !s.ReplaceIfCurrent(negKey, negEntry, cutTestMsg("neg.example.", dns.RcodeServerFailure, 0), time.Time{}, 0) {
		t.Fatal("refresh of a still-current negative entry must succeed")
	}
}

func TestStore_ReplaceIfCurrent_ConcurrentSingleWinner(t *testing.T) {
	s := NewStore(
		NewPositiveCache(1024, minTTL, maxTTL, &CacheMetrics{}),
		NewNegativeCache(1024, minTTL, time.Hour, &CacheMetrics{}),
		CacheConfig{},
	)

	q := dns.Question{Name: "cas-race.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := CacheKey{Question: q, CD: false}.Hash()
	s.SetFromResponseWithKey(key, cutTestMsg(q.Name, dns.RcodeSuccess, 60), time.Time{}, 0)
	expected, ok := s.LookupByKey(key)
	if !ok {
		t.Fatal("seed entry missing")
	}

	start := make(chan struct{})
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 128 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if s.ReplaceIfCurrent(key, expected, cutTestMsg(q.Name, dns.RcodeSuccess, 120), time.Time{}, 0) {
				winners.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Fatalf("successful concurrent replacements = %d, want exactly 1", got)
	}
	if current, ok := s.LookupByKey(key); !ok || current == expected {
		t.Fatal("winning replacement was not published")
	}
}

// TestWriteMsg_CutUntilSeam drives the middleware seam end to end
// within the cache package: a downstream handler (standing in for the
// resolver) folds a delegation-cut deadline into the request's
// ResponseMeta; the cache ResponseWriter must bound the stored entry
// with it.
func TestWriteMsg_CutUntilSeam(t *testing.T) {
	cfg := &config.Config{CacheSize: 1024, Expire: 600}
	c := New(cfg)
	defer c.Stop()

	cut := time.Now().Add(90 * time.Second)
	const cutKey = uint64(0xabcdef)

	resolver := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		middleware.ResponseMetaFrom(ctx).BoundCutFor(cut, cutKey)
		resp := cutTestMsg("seam.example.", dns.RcodeSuccess, 300)
		resp.SetReply(ch.Request)
		resp.Answer = cutTestMsg("seam.example.", dns.RcodeSuccess, 300).Answer
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	req := new(dns.Msg)
	req.SetQuestion("seam.example.", dns.TypeA)
	req.RecursionDesired = true

	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c, resolver})
	ch.Reset(w, req)
	ch.Next(context.Background())

	key := CacheKey{Question: req.Question[0], CD: false}.Hash()
	entry, ok := c.store.LookupByKey(key)
	if !ok {
		t.Fatal("response was not cached")
	}
	if !entry.cutUntil.Equal(cut) {
		t.Fatalf("entry cutUntil = %v, want the resolver-reported cut %v", entry.cutUntil, cut)
	}
	if entry.cutKey != cutKey {
		t.Fatalf("entry cutKey = %#x, want resolver-reported key %#x", entry.cutKey, cutKey)
	}
}

func TestWriteMsg_CNAMEChainUsesShortestCut(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	longCut := time.Now().Add(10 * time.Minute)
	shortCut := time.Now().Add(90 * time.Second)
	const longKey, shortKey = uint64(0x401), uint64(0x402)

	targetHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		middleware.ResponseMetaFrom(ctx).BoundCutFor(shortCut, shortKey)
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "target.short.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 44},
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
	c.SetQueryer(&cutTestQueryer{handlers: []middleware.Handler{c, targetHandler}})

	outerHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		middleware.ResponseMetaFrom(ctx).BoundCutFor(longCut, longKey)
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		resp.Answer = []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "alias.long.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "target.short.",
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	req := new(dns.Msg)
	req.SetQuestion("alias.long.", dns.TypeA)
	req.RecursionDesired = true
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c, outerHandler})
	ch.Reset(w, req)
	ch.Next(context.Background())

	if !w.Written() {
		t.Fatal("CNAME chase wrote no response")
	}
	if len(w.Msg().Answer) != 2 {
		t.Fatalf("CNAME chase response answers = %d, want CNAME + A", len(w.Msg().Answer))
	}
	if got := ch.Meta.CutUntil(); !got.Equal(shortCut) || ch.Meta.CutKey() != shortKey {
		t.Fatalf("request-tree cut = (%v, %#x), want shortest target cut (%v, %#x)", got, ch.Meta.CutKey(), shortCut, shortKey)
	}

	for _, name := range []string{"alias.long.", "target.short."} {
		q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		entry, ok := c.store.LookupByKey(CacheKey{Question: q, CD: false}.Hash())
		if !ok {
			t.Fatalf("%s cache entry missing", name)
		}
		if !entry.cutUntil.Equal(shortCut) || entry.cutKey != shortKey {
			t.Fatalf("%s cut = (%v, %#x), want shortest chain cut (%v, %#x)", name, entry.cutUntil, entry.cutKey, shortCut, shortKey)
		}
	}
}

func TestWriteMsg_ForwarderAndLocalAnswersRemainUnbounded(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	boundedCut := time.Now().Add(time.Minute)
	h := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		if ch.Request.Question[0].Name == "bounded.example." {
			middleware.ResponseMetaFrom(ctx).BoundCutFor(boundedCut, 0x501)
		}
		resp := cutTestMsg(ch.Request.Question[0].Name, dns.RcodeSuccess, 300)
		resp.SetReply(ch.Request)
		resp.Answer = cutTestMsg(ch.Request.Question[0].Name, dns.RcodeSuccess, 300).Answer
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
	ch := middleware.NewChain([]middleware.Handler{c, h})

	query := func(name string) *CacheEntry {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		req.RecursionDesired = true
		w := mock.NewWriter("udp", "127.0.0.1:0")
		ch.Reset(w, req)
		ch.Next(context.Background())
		entry, ok := c.store.LookupByKey(CacheKey{Question: req.Question[0], CD: false}.Hash())
		if !ok {
			t.Fatalf("%s was not cached", name)
		}
		return entry
	}

	if entry := query("bounded.example."); entry.cutUntil.IsZero() {
		t.Fatal("test setup: bounded resolver-style answer did not carry a cut")
	}
	for _, name := range []string{"local.example.", "forwarded.example."} {
		entry := query(name)
		if !entry.cutUntil.IsZero() || entry.cutKey != 0 {
			t.Fatalf("%s inherited pooled metadata from a prior request: cut=(%v, %#x)", name, entry.cutUntil, entry.cutKey)
		}
	}
}
