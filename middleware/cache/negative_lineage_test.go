package cache

import (
	"context"
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
	c := New(&config.Config{CacheSize: 1024, Expire: 600})
	defer c.Stop()

	const alias, target = "alias.lineage.", "target.lineage."

	// A denial for the target, with the short lifetime an authority near the
	// end of its negative TTL would hand out.
	targetHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
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
	c.SetQueryer(&cutTestQueryer{handlers: []middleware.Handler{c, targetHandler}})
	outerHandler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
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
		t.Skip("the merged answer was not cached; nothing to bound")
	}

	if got := entryExpiry(aliasEntry); got.After(targetExpiry) {
		t.Fatalf(
			"merged alias entry outlives the target proof it was built from:\n"+
				"  alias expires  %v\n  target expires %v\n  overhang       %v\n"+
				"  alias cutUntil %v (zero means no bound was inherited)",
			got, targetExpiry, got.Sub(targetExpiry), aliasEntry.cutUntil)
	}
}
