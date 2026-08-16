package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// entryExpiry is the absolute instant past which an entry may not be served:
// its own lifetime, further bounded by the delegation lease it inherited.
func entryExpiry(e *CacheEntry) time.Time {
	expiry := e.stored.Add(e.ttl)
	if !e.cutUntil.IsZero() && e.cutUntil.Before(expiry) {
		return e.cutUntil
	}
	return expiry
}

// TestCNAMEChainInheritsCachedTargetLifetime pins the lineage rule for a
// derived answer: an alias entry assembled from a target the cache supplied
// must not outlive that target.
//
// The existing shortest-cut test covers the case where the target leg is
// resolved, because resolution folds the leg's cut into the request meta. A
// target served from cache folds nothing — nothing calls BoundCutFor on a hit
// — so the merged answer is stored with no bound at all, and the TTL floor
// then extends a nearly-expired denial proof to the cache's minimum.
func TestCNAMEChainInheritsCachedTargetLifetime(t *testing.T) {
	// Both sub-query shapes a Queryer may take. The built-in pipeline hands
	// the nested chain an internal writer, which keeps derived work off the
	// byte path; SetQueryer is public and does not require that, so a
	// wire-capable queryer reaches the byte path with a derived request. The
	// rule has to hold either way — it cannot rest on a contract the API
	// does not enforce.
	for _, tc := range []struct {
		name    string
		queryer func([]middleware.Handler) middleware.Queryer
	}{
		{"internal writer", func(h []middleware.Handler) middleware.Queryer {
			return &internalQueryer{handlers: h}
		}},
		{"wire-capable writer", func(h []middleware.Handler) middleware.Queryer {
			return &cutTestQueryer{handlers: h}
		}},
		{"wire write reports a transport failure", func(h []middleware.Handler) middleware.Queryer {
			return &failingWireQueryer{handlers: h}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertChainInheritsTargetLifetime(t, tc.queryer)
		})
	}
}

func assertChainInheritsTargetLifetime(
	t *testing.T,
	newQueryer func([]middleware.Handler) middleware.Queryer,
) {
	t.Helper()
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	const alias, target = "alias.lineage.", "target.lineage."

	// A denial for the target, with the short lifetime an authority near the
	// end of its negative TTL would hand out.
	targetHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Rcode = dns.RcodeNameError
		resp.Ns = []dns.RR{&dns.SOA{
			Hdr: dns.RR_Header{
				Name: "lineage.", Rrtype: dns.TypeSOA,
				Class: dns.ClassINET, Ttl: 1,
			},
			Ns: "ns.lineage.", Mbox: "hostmaster.lineage.",
			Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minttl: 1,
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	// Prime the target so the chase below is served from cache rather than
	// resolved — the case in which no cut is folded into the meta.
	primeReq := new(dns.Msg)
	primeReq.SetQuestion(target, dns.TypeA)
	primeReq.RecursionDesired = true
	primeChain := middleware.NewChain([]middleware.Handler{c, targetHandler})
	primeChain.Reset(mock.NewWriter("udp", "127.0.0.1:0"), primeReq)
	primeChain.Next(context.Background())

	targetKey := CacheKey{Question: dns.Question{
		Name: target, Qtype: dns.TypeA, Qclass: dns.ClassINET,
	}, CD: false}.Hash()
	targetEntry, ok := c.store.LookupByKey(targetKey)
	if !ok {
		t.Fatal("the target denial was not cached")
	}
	// Age the target so it is near the end of its life when the alias asks
	// for it — the state a cached denial spends most of its time in, and the
	// one where the floor below has the most to extend.
	targetEntry.stored = targetEntry.stored.Add(-targetEntry.ttl + time.Second)
	targetExpiry := entryExpiry(targetEntry)

	// The alias is resolved, and its chase finds the target in cache.
	c.SetQueryer(newQueryer([]middleware.Handler{c, targetHandler}))
	outerHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Answer = []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name: alias, Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: 300,
			},
			Target: target,
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	req := new(dns.Msg)
	req.SetQuestion(alias, dns.TypeA)
	req.RecursionDesired = true
	chain := middleware.NewChain([]middleware.Handler{c, outerHandler})
	chain.Reset(mock.NewWriter("udp", "127.0.0.1:0"), req)
	chain.Next(context.Background())

	aliasKey := CacheKey{Question: req.Question[0], CD: false}.Hash()
	aliasEntry, ok := c.store.LookupByKey(aliasKey)
	if !ok {
		t.Fatal("the merged answer was not cached, so the lineage rule was not exercised")
	}

	if got := entryExpiry(aliasEntry); got.After(targetExpiry) {
		t.Fatalf(
			"merged alias entry outlives the target proof it was built from:\n"+
				"  alias expires  %v\n  target expires %v\n  overhang       %v\n"+
				"  alias cutUntil %v (zero means no bound was inherited)",
			got, targetExpiry, got.Sub(targetExpiry), aliasEntry.cutUntil)
	}
}

// internalQueryer models the production sub-query path: middleware.Queryer
// hands the nested chain a writer that reports Internal(), which is what
// keeps derived work off the byte-serving path. A test queryer writing as an
// external client would take the byte path and prove nothing about the code
// production actually runs.
type internalQueryer struct {
	handlers []middleware.Handler
}

func (q *internalQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	w := mock.NewWriter("udp", "127.0.0.255:0")
	if !w.Internal() {
		panic("mock writer did not report an internal request")
	}
	ch := middleware.NewChain(q.handlers)
	ch.Reset(w, req)
	ch.Next(ctx)
	if !w.Written() {
		return nil, middleware.ErrNoResponse
	}
	return w.Msg(), nil
}

// TestDenialProofLookupReportsEarliestExpiry pins the bound an RFC 8198
// answer carries out with it. The synthesized response is only as live as the
// records it was built from, and a caller that folds a later instant would
// let the TTL floor re-publish a proof with seconds left.
func TestDenialProofLookupReportsEarliestExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	cache := newDenialProofTestCache(&now, 64, 32, maxDenialProofTTL)

	// A NODATA denial: the owner exists, the queried type does not.
	fixture := newDenialProofNSECFixture(
		t, now, "www.example.", dns.TypeAAAA, dns.RcodeSuccess, "example.",
		[2]string{"www.example.", "z.example."},
	)
	if !cache.record(fixture.msg, "example.", time.Time{}) {
		t.Fatal("the proof was not admitted")
	}

	snapshot := denialProofOnlySnapshot(t, cache)
	want := snapshot.soa.expires
	for _, entry := range snapshot.nsec {
		if entry.expires.Before(want) {
			want = entry.expires
		}
	}

	_, _, _, expires, ok := cache.lookupWithMeta(
		denialProofTestRequest("www.example.", dns.TypeAAAA, true), nil)
	if !ok {
		t.Fatal("the proof did not answer")
	}
	if !expires.Equal(want) {
		t.Fatalf("reported expiry %v, want the earliest record expiry %v",
			expires, want)
	}
}

// TestStoreGetWithContextBindsEntryLifetime pins the lineage rule on the
// resolver-private path. DS and DNSKEY lookups come through here, and what
// they return is folded into whatever the resolver is validating — so the
// answer's own lifetime has to bound the request tree.
func TestStoreGetWithContextBindsEntryLifetime(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	const name = "ds.lineage."
	handler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name: name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 300,
			},
			A: []byte{192, 0, 2, 9},
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	primeReq := new(dns.Msg)
	primeReq.SetQuestion(name, dns.TypeA)
	primeReq.RecursionDesired = true
	primeChain := middleware.NewChain([]middleware.Handler{c, handler})
	primeChain.Reset(mock.NewWriter("udp", "127.0.0.1:0"), primeReq)
	primeChain.Next(context.Background())

	key := CacheKey{Question: primeReq.Question[0], CD: false}.Hash()
	entry, ok := c.store.LookupByKey(key)
	if !ok {
		t.Fatal("the answer was not cached")
	}

	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	if _, ok := c.store.GetWithContext(ctx, primeReq); !ok {
		t.Fatal("the resolver-private lookup missed")
	}

	got, _ := meta.Cut()
	if want := entryExpiry(entry); !got.Equal(want) {
		t.Fatalf("request tree bound to %v, want the entry's expiry %v", got, want)
	}
}

// failingWireWriter hands the body to the writer beneath it — which retains
// it and marks the response written — and then reports a transport failure
// that is not a fallback. The cache treats that outcome as terminal, and a
// caller reading the response back through Msg() still gets the answer, so
// the lifetime binding has to happen there too.
type failingWireWriter struct {
	middleware.ResponseWriter
}

var errWireTransport = errors.New("cache: synthetic transport failure")

func (w *failingWireWriter) WireReady() (middleware.WireCapability, bool) {
	next, ok := w.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.WireCapability{}, false
	}
	return next.WireReady()
}

func (w *failingWireWriter) WriteWire(body []byte, info middleware.WireInfo) error {
	next, ok := w.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.ErrWireFallback
	}
	if err := next.WriteWire(body, info); err != nil {
		return err
	}
	return errWireTransport
}

// failingWireQueryer is the wire-capable sub-query path with that writer.
type failingWireQueryer struct {
	handlers []middleware.Handler
}

func (q *failingWireQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := middleware.NewChain(q.handlers)
	ch.Reset(w, req)
	ch.Writer = &failingWireWriter{ResponseWriter: ch.Writer}
	ch.Next(ctx)
	if !w.Written() {
		return nil, middleware.ErrNoResponse
	}
	return w.Msg(), nil
}

// TestChildEntryKeepsItsOwnLifetime is the other half of the lineage rule.
// A derived answer must not outlive its source — but the source must not be
// shortened to the deriver's lifetime either. They share one request tree,
// and today they share one bound, so a nearly expired alias drags a freshly
// resolved target down to its own seconds.
//
// Safe, and expensive: the target's entry expires almost immediately and the
// next query for it resolves again.
func TestChildEntryKeepsItsOwnLifetime(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	const alias, target = "alias.child.", "target.child."

	// The target is resolved fresh, with a long lifetime of its own.
	targetHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name: target, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 300,
			},
			A: []byte{192, 0, 2, 7},
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	// The alias is cached and nearly expired when the client asks for it.
	aliasHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Answer = []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name: alias, Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: 300,
			},
			Target: target,
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	c.SetQueryer(&internalQueryer{handlers: []middleware.Handler{c, targetHandler}})

	primeReq := new(dns.Msg)
	primeReq.SetQuestion(alias, dns.TypeA)
	primeReq.RecursionDesired = true
	primeChain := middleware.NewChain([]middleware.Handler{c, aliasHandler})
	primeChain.Reset(mock.NewWriter("udp", "127.0.0.1:0"), primeReq)
	primeChain.Next(context.Background())

	aliasKey := CacheKey{Question: primeReq.Question[0], CD: false}.Hash()
	aliasEntry, ok := c.store.LookupByKey(aliasKey)
	if !ok {
		t.Fatal("the alias was not cached")
	}
	// Age the alias to a second of remaining life, and drop the target so the
	// chase below has to resolve it fresh.
	aliasEntry.stored = aliasEntry.stored.Add(-aliasEntry.ttl + time.Second)
	targetKey := CacheKey{Question: dns.Question{
		Name: target, Qtype: dns.TypeA, Qclass: dns.ClassINET,
	}, CD: false}.Hash()
	c.store.positive.Remove(targetKey)
	c.store.negative.Remove(targetKey)

	req := new(dns.Msg)
	req.SetQuestion(alias, dns.TypeA)
	req.RecursionDesired = true
	chain := middleware.NewChain([]middleware.Handler{c, aliasHandler})
	chain.Reset(mock.NewWriter("udp", "127.0.0.1:0"), req)
	chain.Next(context.Background())

	targetEntry, ok := c.store.LookupByKey(targetKey)
	if !ok {
		t.Fatal("the chase did not cache the target it resolved")
	}
	if got := time.Until(entryExpiry(targetEntry)); got < 30*time.Second {
		t.Fatalf("a freshly resolved target was stored with %v of life, "+
			"cut down to the alias that happened to ask for it", got)
	}
}

// boundThenSilentQueryer is a sub-query that observes a short delegation cut
// and then produces nothing. Its lineage belongs to an answer that was never
// assembled, so the deriving request must not inherit it.
type boundThenSilentQueryer struct {
	deadline time.Time
}

func (q *boundThenSilentQueryer) Query(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
	middleware.ResponseMetaFrom(ctx).BoundCutFor(q.deadline, 0)
	return nil, middleware.ErrNoResponse
}

// TestUnusedSubQueryLineageIsNotInherited pins when a sub-query's bound
// counts. It travels to the deriving request because the composed answer
// carries the sub-query's records — so a sub-query that contributed no
// records must not shorten anything.
func TestUnusedSubQueryLineageIsNotInherited(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	const alias, target = "alias.unused.", "target.unused."

	c.SetQueryer(&boundThenSilentQueryer{deadline: time.Now().Add(time.Second)})

	aliasHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Answer = []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name: alias, Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: 300,
			},
			Target: target,
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	req := new(dns.Msg)
	req.SetQuestion(alias, dns.TypeA)
	req.RecursionDesired = true
	chain := middleware.NewChain([]middleware.Handler{c, aliasHandler})
	chain.Reset(mock.NewWriter("udp", "127.0.0.1:0"), req)
	chain.Next(context.Background())

	entry, ok := c.store.LookupByKey(CacheKey{Question: req.Question[0], CD: false}.Hash())
	if !ok {
		t.Fatal("the alias was not cached")
	}
	if got := time.Until(entryExpiry(entry)); got < 30*time.Second {
		t.Fatalf("the alias was bound to %v by a sub-query that produced "+
			"nothing for it", got)
	}
}
