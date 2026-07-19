package resolver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	cachemw "github.com/semihalev/sdns/middleware/cache"
)

// chainQueryer runs a request through the given handlers — the
// minimal stand-in for the sub-pipeline Queryer that sdns.go wiring
// installs in production.
type chainQueryer struct{ handlers []middleware.Handler }

func (q *chainQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	w := mock.NewWriter("tcp", "127.0.0.255:0")
	ch := middleware.NewChain(q.handlers)
	ch.Reset(w, req)
	ch.Next(ctx)
	if !w.Written() {
		return nil, middleware.ErrNoResponse
	}
	return w.Msg(), nil
}

// TestGhostDomain_AnswerCacheAndPrefetch_FullPipeline is the full
// parent-referral → answer-cache → prefetch → withdrawal regression
// for GHSA-mqfw-f48p-2vc8, covering the two layers above the
// delegation cache:
//
//   - Phase 1b (answer-cache ghost): an answer with a long TTL (600s)
//     obtained through a short delegation lease (1s) must stop being
//     served when the lease expires — the entry's cutUntil, fed
//     through the Chain.Meta seam, overrides both the answer TTL and
//     the 5s MinTTL floor.
//   - Phase 2 (late prefetch overwrite): a prefetch refresh that
//     started before the withdrawal and returns after a newer
//     NXDOMAIN landed must be dropped by the pointer-CAS write-back,
//     not resurrect the withdrawn domain.
//
// Topology: mock root delegates ghost. (NS TTL 1s, TEST-NET glue
// remapped to a loopback listener); the former child keeps answering
// www.ghost. with a 600s TTL. The refresh is made deterministically
// "late" by blocking the child's second answer on a channel the test
// releases only after the withdrawal NXDOMAIN is cached.
func TestGhostDomain_AnswerCacheAndPrefetch_FullPipeline(t *testing.T) {
	var ignore int64

	softNeg := func(zone string) *dns.Msg {
		m := &dns.Msg{}
		m.Authoritative = true
		if zone == "." {
			m.Ns = []dns.RR{mustRR(t, ". 30 IN SOA a.root. hostmaster.root. 1 30 30 30 30")}
		} else {
			m.Ns = []dns.RR{mustRR(t, zone+" 30 IN SOA ns."+zone+" hostmaster."+zone+" 1 30 30 30 30")}
		}
		return m
	}

	// ghost. — the former child. Keeps answering with a LONG TTL. The
	// second-and-later A query is the prefetch refresh: signal it and
	// block until the test releases it (bounded well under the 2s
	// exchange timeout so the refresh completes rather than erroring).
	var wwwQueries atomic.Int64
	var signalStart sync.Once
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	ghostAddr, stopGhost := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeA && dns.CanonicalName(q.Name) == "www.ghost." {
			if wwwQueries.Add(1) >= 2 {
				signalStart.Do(func() { close(refreshStarted) })
				select {
				case <-releaseRefresh:
				case <-time.After(1900 * time.Millisecond):
				}
			}
			m := &dns.Msg{}
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, "www.ghost. 600 IN A 192.0.2.55")}
			return m
		}
		return softNeg("ghost.")
	})
	defer stopGhost()

	// root — delegates ghost. with a 1s lease until the withdrawal
	// flag flips, then answers NXDOMAIN for everything under it.
	var withdrawn atomic.Bool
	rootAddr, stopRoot := startMockAuth(t, &ignore, func(q dns.Question) *dns.Msg {
		if dns.CanonicalName(q.Name) == "." && q.Qtype == dns.TypeNS {
			m := &dns.Msg{}
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, ". 3600 IN NS a.root.")}
			return m
		}
		if q.Qtype == dns.TypeDS {
			return softNeg(".")
		}
		if dns.IsSubDomain("ghost.", dns.CanonicalName(q.Name)) || dns.CanonicalName(q.Name) == "ghost." {
			if withdrawn.Load() {
				m := softNeg(".")
				m.Rcode = dns.RcodeNameError
				return m
			}
			m := &dns.Msg{} // referral
			m.Ns = []dns.RR{mustRR(t, "ghost. 1 IN NS ns.ghost.")}
			m.Extra = []dns.RR{mustRR(t, "ns.ghost. 1 IN A 192.0.2.21")}
			return m
		}
		return softNeg(".")
	})
	defer stopRoot()

	remap := map[string]string{"192.0.2.21:53": ghostAddr}
	mapper := func(addr string) string {
		if to, ok := remap[addr]; ok {
			return to
		}
		return addr
	}

	base := makeTestConfig()
	cfg := *base
	cfg.RootServers = []string{rootAddr}
	cfg.Root6Servers = nil
	cfg.DNSSEC = "off"
	cfg.CacheSize = 1024
	cfg.Prefetch = 90
	cfg.RateLimit = 0

	h := New(&cfg)
	h.resolver.resolveTarget.Store(&mapper)

	cm := cachemw.New(&cfg)
	defer cm.Stop()
	refreshPipeline := &chainQueryer{handlers: []middleware.Handler{h}}
	cm.SetPrefetchQueryer(refreshPipeline)
	cm.SetQueryer(refreshPipeline)

	ask := func(label string) *dns.Msg {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion("www.ghost.", dns.TypeA)
		w := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain([]middleware.Handler{cm, h})
		ch.Reset(w, req)
		ch.Next(context.Background())
		if !w.Written() {
			t.Fatalf("%s: no response written", label)
		}
		return w.Msg()
	}

	// 1. Prime the cache: 600s answer under the 1s ghost. lease.
	if resp := ask("prime"); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("prime: expected a positive answer, got rcode=%s answers=%d",
			dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	probe := new(dns.Msg)
	probe.SetQuestion("www.ghost.", dns.TypeA)
	cacheStore, ok := cm.Store().(*cachemw.Store)
	if !ok {
		t.Fatal("cache StoreProvider did not return *cache.Store")
	}
	claimedEntry, ok := cacheStore.Lookup(probe)
	if !ok {
		t.Fatal("prime: cached entry not found for prefetch claim tracking")
	}

	// 2. Cache hit claims the prefetch; wait until the refresh has
	// actually reached the former child (and is now held there).
	if resp := ask("hit"); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("hit: expected a positive answer, got rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("prefetch refresh never reached the former child")
	}

	// 3. The parent withdraws the delegation while the refresh is in
	// flight, and the 1s lease (delegation AND answer cut) runs out.
	withdrawn.Store(true)
	time.Sleep(1300 * time.Millisecond)

	// 4. Phase 1b: the 600s answer must NOT be served past its 1s cut
	// (without cutUntil this is a cache hit — TTL and the 5s MinTTL
	// floor both leave the entry valid). The miss re-resolves via the
	// parent and caches the withdrawal NXDOMAIN.
	if resp := ask("post-withdrawal"); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("ghost answer served past its delegation cut: rcode=%s answers=%d",
			dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}

	// 5. Phase 2: release the stale refresh. Its positive answer must
	// be dropped by the pointer-CAS write-back — the entry it claimed
	// was replaced by the NXDOMAIN.
	close(releaseRefresh)

	// processPrefetch releases the captured entry's claim in a defer after
	// ReplaceIfCurrent returns. Waiting for the flag to clear proves the CAS
	// attempt completed; a fixed sleep could let this test pass before a slow
	// worker performed a later resurrection.
	claimDeadline := time.Now().Add(2 * time.Second)
	for !claimedEntry.ShouldPrefetch(int(cfg.Prefetch)) && time.Now().Before(claimDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !claimedEntry.ShouldPrefetch(int(cfg.Prefetch)) {
		t.Fatal("late prefetch did not finish its CAS attempt")
	}

	if resp := ask("after-late-prefetch"); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("late prefetch resurrected the withdrawn domain: rcode=%s answers=%d",
			dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
}
