package cache

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

func clientECSMarkerExchange(
	t testing.TB,
	cfg *config.Config,
	cache *Cache,
	downstream middleware.Handler,
	req *dns.Msg,
) *dns.Msg {
	t.Helper()

	writer := mock.NewWriter("udp", "203.0.113.5:53000")
	chain := middleware.NewChain([]middleware.Handler{
		edns.New(cfg),
		cache,
		downstream,
	})
	chain.Reset(writer, req)
	chain.Next(context.Background())
	if !writer.Written() {
		t.Fatal("EDNS/cache pipeline wrote no response")
	}
	return writer.Msg()
}

func clientECSMarkerConfigs() map[string]func() *config.Config {
	return map[string]func() *config.Config{
		"policy disabled": func() *config.Config {
			return &config.Config{CacheSize: 1024, Expire: 300}
		},
		"client outside allow-list": func() *config.Config {
			cfg := &config.Config{CacheSize: 1024, Expire: 300}
			cfg.ECS = config.ECSConfig{
				Enabled:        true,
				ForwardV4Max:   24,
				ForwardV6Max:   56,
				ClientNetworks: []string{"10.0.0.0/8"},
			}
			return cfg
		},
	}
}

func TestClientECSMarkerSurvivesEDNSStripAndBypassesSharedDenial(t *testing.T) {
	for name, newConfig := range clientECSMarkerConfigs() {
		t.Run(name, func(t *testing.T) {
			cfg := newConfig()
			cache := New(cfg)
			defer cache.Stop()

			// Install both RFC 8020 and RFC 8198 state without going through
			// the request path under test. If either shared index is consulted
			// after EDNS strips ECS, it terminates one of the probes below.
			cutSeed := nxCutRequest(nxCutDeniedName, dns.TypeA)
			cutProof := nxCutValidatedResponse(cutSeed, nxCutDeniedName, nxCutZone)
			if !cache.store.RecordNXDomainCut(
				cutProof,
				nxCutDeniedName,
				nxCutZone,
				time.Time{},
			) {
				t.Fatal("failed to install RFC 8020 cut")
			}

			const nsec3Owner = "ecs-marker.p6.example."
			nsec3Proof := newDenialProofNSEC3Fixture(
				t,
				time.Now().UTC(),
				nsec3Owner,
				p6NSEC3Zone,
				"",
				0,
				0,
			)
			aggressiveNegativeMakeSignaturesPackable(nsec3Proof.msg)
			if !cache.store.RecordDenialProof(
				nsec3Proof.msg,
				p6NSEC3Zone,
				middleware.ValidatedNegativeProofNSEC3,
				time.Time{},
			) {
				t.Fatal("failed to install RFC 8198 NSEC3 proof")
			}

			limiter := newP6CountingCryptoLimiter(8)
			cache.SetDNSSECCryptoLimiter(limiter)

			var downstreamCalls atomic.Int32
			downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
				downstreamCalls.Add(1)
				if hasEDNSClientSubnet(ch.Request.Msg()) {
					t.Error("EDNS forwarding policy did not strip client ECS")
				}
				if !middleware.HasClientECS(ctx) {
					t.Error("raw client ECS marker did not reach cache downstream")
				}
				_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
				ch.Cancel()
			})

			cutProbe := aggressiveNegativeRequestWithECS(
				"child."+nxCutDeniedName,
				dns.TypeMX,
			)
			got := clientECSMarkerExchange(t, cfg, cache, downstream, cutProbe)
			if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
				t.Fatalf("stripped-ECS request consumed RFC 8020 cut: %#v", got)
			}

			nsec3Probe := aggressiveNegativeRequestWithECS(nsec3Owner, dns.TypeTXT)
			got = clientECSMarkerExchange(t, cfg, cache, downstream, nsec3Probe)
			if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
				t.Fatalf("stripped-ECS request consumed RFC 8198 proof: %#v", got)
			}

			if got := downstreamCalls.Load(); got != 2 {
				t.Fatalf("shared denial lookup terminated a probe; downstream calls=%d, want 2", got)
			}
			if got := limiter.calls.Load(); got != 0 {
				t.Fatalf("stripped-ECS request performed %d NSEC3 hashes, want 0", got)
			}
		})
	}
}

func TestClientECSMarkerSurvivesEDNSStripAndBlocksSharedDenialAdmission(t *testing.T) {
	for name, newConfig := range clientECSMarkerConfigs() {
		t.Run(name, func(t *testing.T) {
			cfg := newConfig()
			cache := New(cfg)
			defer cache.Stop()

			downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
				if hasEDNSClientSubnet(ch.Request.Msg()) {
					t.Error("EDNS forwarding policy did not strip client ECS")
				}
				if !middleware.HasClientECS(ctx) {
					t.Error("raw client ECS marker did not reach cache downstream")
				}

				resp := nxCutValidatedResponse(ch.Request.Msg(), nxCutDeniedName, nxCutZone)
				nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
			})

			req := nxCutRequestWithECS(nxCutDeniedName, net.IPv4(203, 0, 113, 0).String())
			got := clientECSMarkerExchange(t, cfg, cache, downstream, req)
			if got.Rcode != dns.RcodeNameError {
				t.Fatalf("downstream NXDOMAIN rcode=%s", dns.RcodeToString[got.Rcode])
			}
			if got := cache.store.NXDomainCutLen(); got != 0 {
				t.Fatalf("stripped-ECS request admitted %d RFC 8020 cuts, want 0", got)
			}
			if got := cache.store.DenialProofLen(); got != 0 {
				t.Fatalf("stripped-ECS request admitted %d RFC 8198 entries, want 0", got)
			}
		})
	}
}

type clientECSMarkerPrefetchQueryer struct {
	cache         *Cache
	probe         *dns.Msg
	sawMarker     atomic.Bool
	sawMessageECS atomic.Bool
	consumedProof atomic.Bool
	fired         chan struct{}
}

func (q *clientECSMarkerPrefetchQueryer) Query(
	ctx context.Context,
	req *dns.Msg,
) (*dns.Msg, error) {
	q.sawMarker.Store(middleware.HasClientECS(ctx))
	q.sawMessageECS.Store(hasEDNSClientSubnet(req))
	if _, ok := q.cache.store.GetWithContext(ctx, q.probe.Copy()); ok {
		q.consumedProof.Store(true)
	}

	resp := nxCutValidatedResponse(req, nxCutDeniedName, nxCutZone)
	nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
	close(q.fired)
	return resp, nil
}

func TestClientECSMarkerSurvivesStrippedPrefetchRequest(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    300,
		Prefetch:  50,
	}
	cache := New(cfg)
	defer cache.Stop()

	// A distinct retained NSEC3 proof lets the cache-less refresh queryer
	// exercise Store.GetWithContext. The preserved marker must skip it before
	// acquiring the hash limiter.
	const nsec3Owner = "prefetch-ecs-marker.p6.example."
	nsec3Proof := newDenialProofNSEC3Fixture(
		t,
		time.Now().UTC(),
		nsec3Owner,
		p6NSEC3Zone,
		"",
		0,
		0,
	)
	aggressiveNegativeMakeSignaturesPackable(nsec3Proof.msg)
	if !cache.store.RecordDenialProof(
		nsec3Proof.msg,
		p6NSEC3Zone,
		middleware.ValidatedNegativeProofNSEC3,
		time.Time{},
	) {
		t.Fatal("failed to install prefetch NSEC3 probe")
	}
	proofEntries := cache.store.DenialProofLen()

	limiter := newP6CountingCryptoLimiter(8)
	cache.SetDNSSECCryptoLimiter(limiter)
	queryer := &clientECSMarkerPrefetchQueryer{
		cache: cache,
		probe: aggressiveNegativeRequest(nsec3Owner, dns.TypeTXT, true),
		fired: make(chan struct{}),
	}
	cache.SetPrefetchQueryer(queryer)

	// The raw ECS request will hit this unscoped answer after EDNS strips its
	// option. Age it into the prefetch window without sleeping.
	baseReq := nxCutRequest(nxCutDeniedName, dns.TypeA)
	old := nxCutPositiveResponse(baseReq)
	key := CacheKey{Question: baseReq.Question[0], CD: false}.Hash()
	entry := NewCacheEntryWithKey(old, 5*time.Second, 0, key)
	entry.stored = time.Now().Add(-4 * time.Second)
	cache.positive.Set(key, entry)

	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		t.Error("exact cache hit unexpectedly reached downstream")
		ch.Cancel()
	})
	rawECS := aggressiveNegativeRequestWithECS(nxCutDeniedName, dns.TypeA)
	got := clientECSMarkerExchange(t, cfg, cache, downstream, rawECS)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("triggering cache hit=%#v", got)
	}

	select {
	case <-queryer.fired:
	case <-time.After(2 * time.Second):
		t.Fatal("prefetch queryer did not run")
	}

	refreshed := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		current, ok := cache.positive.Get(key)
		if ok && current != entry && !entry.prefetch.Load() {
			refreshed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !refreshed {
		t.Fatal("prefetch worker did not finish replacing the cache entry")
	}

	if !queryer.sawMarker.Load() {
		t.Fatal("prefetch request lost original client ECS marker")
	}
	if queryer.sawMessageECS.Load() {
		t.Fatal("prefetch message unexpectedly retained stripped ECS option")
	}
	if queryer.consumedProof.Load() {
		t.Fatal("prefetch request consumed shared RFC 8198 proof")
	}
	if got := limiter.calls.Load(); got != 0 {
		t.Fatalf("prefetch request performed %d NSEC3 hashes, want 0", got)
	}
	if got := cache.store.DenialProofLen(); got != proofEntries {
		t.Fatalf("prefetch request changed denial entries from %d to %d", proofEntries, got)
	}
	if got := cache.store.NXDomainCutLen(); got != 0 {
		t.Fatalf("prefetch request admitted %d RFC 8020 cuts, want 0", got)
	}
}
