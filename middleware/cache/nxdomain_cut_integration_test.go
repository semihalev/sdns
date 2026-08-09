package cache

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

const (
	nxCutZone       = "secure.example."
	nxCutDeniedName = "missing.secure.example."
)

// nxCutRequest builds the client-shaped request used by these integration
// tests. DO is enabled so assertions can distinguish a replayed authenticated
// denial proof from an ordinary downstream answer.
func nxCutRequest(name string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.RecursionDesired = true
	req.SetEdns0(1232, true)
	return req
}

func nxCutRequestWithECS(name, address string) *dns.Msg {
	req := nxCutRequest(name, dns.TypeAAAA)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   0,
		Address:       net.ParseIP(address).To4(),
	})
	return req
}

// nxCutValidatedResponse is proof-shaped input for the explicit
// resolver-to-cache trust seam. The signatures are intentionally not
// cryptographically verified here: MarkValidatedDenialResponse represents the
// production resolver having already completed both signature and semantic
// NXDOMAIN verification.
func nxCutValidatedResponse(req *dns.Msg, deniedName, zone string) *dns.Msg {
	const ttl = uint32(300)
	now := time.Now()

	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	resp.RecursionAvailable = true
	resp.AuthenticatedData = true
	resp.Ns = []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
			Ns:      "ns1." + zone,
			Mbox:    "hostmaster." + zone,
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  ttl,
		},
		nxCutRRSIG(zone, dns.TypeSOA, ttl, now),
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "a." + zone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: "z." + zone,
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		},
		nxCutRRSIG("a."+zone, dns.TypeNSEC, ttl, now),
	}
	return resp
}

func nxCutRRSIG(owner string, covered uint16, ttl uint32, now time.Time) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
		TypeCovered: covered,
		Algorithm:   dns.RSASHA256,
		Labels:      uint8(dns.CountLabel(owner)), //nolint:gosec // DNS names have at most 127 labels.
		OrigTtl:     ttl,
		Expiration:  uint32(now.Add(time.Hour).Unix()),  //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		Inception:   uint32(now.Add(-time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		KeyTag:      12345,
		SignerName:  nxCutZone,
		Signature:   "AA==",
	}
}

func nxCutPositiveResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	q := req.Question[0]

	switch q.Qtype {
	case dns.TypeAAAA:
		resp.Answer = []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: q.Qclass, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::53"),
		}}
	case dns.TypeMX:
		resp.Answer = []dns.RR{&dns.MX{
			Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: q.Qclass, Ttl: 300},
			Preference: 10,
			Mx:         "mail.secure.example.",
		}}
	default:
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: q.Qclass, Ttl: 300},
			A:   net.ParseIP("192.0.2.53").To4(),
		}}
	}
	return resp
}

func nxCutExchange(
	t *testing.T,
	cache *Cache,
	downstream middleware.Handler,
	req *dns.Msg,
	remote string,
) *dns.Msg {
	t.Helper()
	writer := mock.NewWriter("udp", remote)
	ch := middleware.NewChain([]middleware.Handler{cache, downstream})
	ch.Reset(writer, req)
	ch.Next(context.Background())
	if !writer.Written() {
		t.Fatal("cache pipeline wrote no response")
	}
	return writer.Msg()
}

func nxCutMark(ctx context.Context, resp *dns.Msg, deniedName, zone string) {
	middleware.MarkValidatedNegativeProofResponse(ctx, resp, middleware.ValidatedNegativeProof{
		Subject:    deniedName,
		Zone:       zone,
		Kind:       negativeProofKind(resp.Ns),
		Aggressive: true,
	})
}

func assertNXCutResponse(t *testing.T, resp, req *dns.Msg) {
	t.Helper()
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if !resp.AuthenticatedData {
		t.Fatal("locally authenticated cut response has AD=0")
	}
	if resp.Id != req.Id {
		t.Fatalf("response ID = %d, want request ID %d", resp.Id, req.Id)
	}
	if len(resp.Question) != 1 || resp.Question[0] != req.Question[0] {
		t.Fatalf("response question = %#v, want %#v", resp.Question, req.Question)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("cut response leaked answer records: %v", resp.Answer)
	}

	var soa, denial, signatures bool
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.SOA:
			soa = true
		case *dns.NSEC, *dns.NSEC3:
			denial = true
		case *dns.RRSIG:
			signatures = true
		}
	}
	if !soa || !denial || !signatures {
		t.Fatalf("cut proof = %v, want SOA + NSEC/NSEC3 + RRSIG", resp.Ns)
	}
}

func TestNXDomainCutIntegrationExactAndDescendantBoundaries(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	calls := 0
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		calls++
		if ch.Request.Question[0].Name == nxCutDeniedName {
			resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
			nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
			_ = ch.Writer.WriteMsg(resp)
			ch.Cancel()
			return
		}
		_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
		ch.Cancel()
	})

	seed := nxCutRequest(nxCutDeniedName, dns.TypeA)
	seed.Id = 100
	if got := nxCutExchange(t, cache, downstream, seed, "192.0.2.1:53000"); got.Rcode != dns.RcodeNameError {
		t.Fatalf("seed rcode = %s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
	}
	if cache.store.NXDomainCutLen() != 1 {
		t.Fatalf("cut entries = %d, want 1", cache.store.NXDomainCutLen())
	}
	if got := cache.Stats()["nxdomain_cut_size"]; got != 1 {
		t.Fatalf("reported cut size = %v, want 1", got)
	}

	exactOtherType := nxCutRequest(nxCutDeniedName, dns.TypeAAAA)
	exactOtherType.Id = 101
	assertNXCutResponse(t, nxCutExchange(t, cache, downstream, exactOtherType, "192.0.2.1:53000"), exactOtherType)

	descendant := nxCutRequest("deep."+nxCutDeniedName, dns.TypeMX)
	descendant.Id = 102
	assertNXCutResponse(t, nxCutExchange(t, cache, downstream, descendant, "192.0.2.1:53000"), descendant)

	if calls != 1 {
		t.Fatalf("exact/different-QTYPE and descendant cut hits reached downstream; calls = %d, want 1", calls)
	}

	for _, name := range []string{"sibling.secure.example.", nxCutZone} {
		req := nxCutRequest(name, dns.TypeA)
		resp := nxCutExchange(t, cache, downstream, req, "192.0.2.1:53000")
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("%s was incorrectly covered by cut: rcode=%s answer=%v",
				name, dns.RcodeToString[resp.Rcode], resp.Answer)
		}
	}
	if calls != 3 {
		t.Fatalf("sibling/ancestor downstream calls = %d, want 3 total", calls)
	}
}

func TestNXDomainCutIntegrationDO0SeedRetainsProofForDO1Hit(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	calls := 0
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		calls++
		resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
		nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	seed := nxCutRequest(nxCutDeniedName, dns.TypeA)
	seed.IsEdns0().SetDo(false)
	if got := nxCutExchange(t, cache, downstream, seed, "192.0.2.10:53000"); got.Rcode != dns.RcodeNameError {
		t.Fatalf("DO=0 seed rcode = %s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
	}

	descendant := nxCutRequest("proof."+nxCutDeniedName, dns.TypeAAAA)
	assertNXCutResponse(t, nxCutExchange(t, cache, downstream, descendant, "192.0.2.10:53000"), descendant)
	if calls != 1 {
		t.Fatalf("DO=1 descendant reached downstream; calls = %d, want 1", calls)
	}
}

func TestNXDomainCutIntegrationRejectsUnmarkedAD(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	const denied = "untrusted.secure.example."
	calls := 0
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		calls++
		if ch.Request.Question[0].Name == denied {
			// Proof-shaped AD=1 input from an untrusted forwarder/plugin must
			// remain an ordinary exact NXDOMAIN cache entry.
			_ = ch.Writer.WriteMsg(nxCutValidatedResponse(ch.Request, denied, nxCutZone))
			ch.Cancel()
			return
		}
		_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
		ch.Cancel()
	})

	seed := nxCutRequest(denied, dns.TypeA)
	if got := nxCutExchange(t, cache, downstream, seed, "192.0.2.2:53000"); got.Rcode != dns.RcodeNameError {
		t.Fatalf("seed rcode = %s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
	}
	if cache.store.NXDomainCutLen() != 0 {
		t.Fatalf("unmarked AD=1 response admitted %d cuts", cache.store.NXDomainCutLen())
	}

	descendant := nxCutRequest("child."+denied, dns.TypeAAAA)
	got := nxCutExchange(t, cache, downstream, descendant, "192.0.2.2:53000")
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("unmarked descendant did not reach downstream: rcode=%s answer=%v",
			dns.RcodeToString[got.Rcode], got.Answer)
	}
	if calls != 2 {
		t.Fatalf("downstream calls = %d, want 2", calls)
	}
}

func TestNXDomainCutIntegrationBypassesCDAndECS(t *testing.T) {
	t.Run("CD=1", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			if ch.Request.Question[0].Name == nxCutDeniedName {
				resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
				nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
				return
			}
			_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
			ch.Cancel()
		})

		_ = nxCutExchange(t, cache, downstream, nxCutRequest(nxCutDeniedName, dns.TypeA), "192.0.2.3:53000")

		cd := nxCutRequest("cd-child."+nxCutDeniedName, dns.TypeAAAA)
		cd.CheckingDisabled = true
		got := nxCutExchange(t, cache, downstream, cd, "192.0.2.3:53000")
		if got.Rcode != dns.RcodeSuccess {
			t.Fatalf("CD=1 request consumed authenticated cut: rcode=%s", dns.RcodeToString[got.Rcode])
		}

		normal := nxCutRequest("normal-child."+nxCutDeniedName, dns.TypeMX)
		assertNXCutResponse(t, nxCutExchange(t, cache, downstream, normal, "192.0.2.3:53000"), normal)
		if calls != 2 {
			t.Fatalf("downstream calls = %d, want seed + CD bypass only", calls)
		}
	})

	t.Run("CD=1 seed cannot admit after response bit is cleared", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			if ch.Request.Question[0].Name == nxCutDeniedName {
				resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
				resp.CheckingDisabled = false
				nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
				return
			}
			_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
			ch.Cancel()
		})

		seed := nxCutRequest(nxCutDeniedName, dns.TypeA)
		seed.CheckingDisabled = true
		_ = nxCutExchange(t, cache, downstream, seed, "192.0.2.30:53000")
		if got := cache.store.NXDomainCutLen(); got != 0 {
			t.Fatalf("CD=1 seed admitted %d cuts after response CD was cleared", got)
		}

		descendant := nxCutRequest("fresh-child."+nxCutDeniedName, dns.TypeAAAA)
		got := nxCutExchange(t, cache, downstream, descendant, "192.0.2.30:53000")
		if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
			t.Fatalf("descendant consumed a CD=1-derived cut: rcode=%s answer=%v",
				dns.RcodeToString[got.Rcode], got.Answer)
		}
		if calls != 2 {
			t.Fatalf("downstream calls = %d, want CD seed + descendant miss", calls)
		}
	})

	t.Run("valid ECS scope", func(t *testing.T) {
		cfg := &config.Config{CacheSize: 1024, Expire: 300}
		cfg.ECS = config.ECSConfig{
			Enabled:      true,
			ForwardV4Max: 24,
			ForwardV6Max: 56,
			MinScopeV4:   24,
			MinScopeV6:   56,
		}
		cache := New(cfg)
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			if ch.Request.Question[0].Name == nxCutDeniedName {
				resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
				nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
				return
			}
			_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
			ch.Cancel()
		})

		_ = nxCutExchange(t, cache, downstream, nxCutRequest(nxCutDeniedName, dns.TypeA), "203.0.113.9:53000")

		ecsReq := nxCutRequestWithECS("ecs-child."+nxCutDeniedName, "203.0.113.0")
		got := nxCutExchange(t, cache, downstream, ecsReq, "203.0.113.9:53000")
		if got.Rcode != dns.RcodeSuccess {
			t.Fatalf("ECS-scoped request consumed shared cut: rcode=%s", dns.RcodeToString[got.Rcode])
		}
		if calls != 2 {
			t.Fatalf("downstream calls = %d, want seed + ECS bypass", calls)
		}
	})

	t.Run("ECS-scoped seed cannot publish a shared cut", func(t *testing.T) {
		cfg := &config.Config{CacheSize: 1024, Expire: 300}
		cfg.ECS = config.ECSConfig{
			Enabled:      true,
			ForwardV4Max: 24,
			ForwardV6Max: 56,
			MinScopeV4:   24,
			MinScopeV6:   56,
		}
		cache := New(cfg)
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			if ch.Request.Question[0].Name == nxCutDeniedName {
				resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
				nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
				return
			}
			_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
			ch.Cancel()
		})

		seed := nxCutRequestWithECS(nxCutDeniedName, "203.0.113.0")
		if got := nxCutExchange(t, cache, downstream, seed, "203.0.113.10:53000"); got.Rcode != dns.RcodeNameError {
			t.Fatalf("ECS seed rcode = %s, want NXDOMAIN", dns.RcodeToString[got.Rcode])
		}
		if got := cache.store.NXDomainCutLen(); got != 0 {
			t.Fatalf("ECS-scoped seed admitted %d shared cuts", got)
		}

		descendant := nxCutRequest("unscoped-child."+nxCutDeniedName, dns.TypeA)
		got := nxCutExchange(t, cache, downstream, descendant, "203.0.113.10:53000")
		if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
			t.Fatalf("unscoped descendant consumed an ECS-derived cut: rcode=%s answer=%v",
				dns.RcodeToString[got.Rcode], got.Answer)
		}
		if calls != 2 {
			t.Fatalf("downstream calls = %d, want ECS seed + unscoped miss", calls)
		}
	})
}

func TestNXDomainCutIntegrationLookupPrecedence(t *testing.T) {
	t.Run("exact positive before ancestor cut", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		const child = "positive.missing.secure.example."
		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			if ch.Request.Question[0].Name == nxCutDeniedName {
				resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
				nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
				return
			}
			_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
			ch.Cancel()
		})

		childReq := nxCutRequest(child, dns.TypeA)
		first := nxCutExchange(t, cache, downstream, childReq, "192.0.2.4:53000")
		if first.Rcode != dns.RcodeSuccess || len(first.Answer) != 1 {
			t.Fatalf("positive seed = rcode %s, answer %v", dns.RcodeToString[first.Rcode], first.Answer)
		}
		_ = nxCutExchange(t, cache, downstream, nxCutRequest(nxCutDeniedName, dns.TypeAAAA), "192.0.2.4:53000")

		hit := nxCutExchange(t, cache, downstream, childReq, "192.0.2.4:53000")
		if hit.Rcode != dns.RcodeSuccess || len(hit.Answer) != 1 {
			t.Fatalf("ancestor cut shadowed exact positive: rcode=%s answer=%v",
				dns.RcodeToString[hit.Rcode], hit.Answer)
		}
		if calls != 2 {
			t.Fatalf("downstream calls = %d, want positive seed + cut seed", calls)
		}
	})

	t.Run("cut before RFC 9520 failure", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			resp := nxCutValidatedResponse(ch.Request, nxCutDeniedName, nxCutZone)
			nxCutMark(ctx, resp, nxCutDeniedName, nxCutZone)
			_ = ch.Writer.WriteMsg(resp)
			ch.Cancel()
		})

		_ = nxCutExchange(t, cache, downstream, nxCutRequest(nxCutDeniedName, dns.TypeA), "192.0.2.5:53000")

		descendant := nxCutRequest("failed."+nxCutDeniedName, dns.TypeAAAA)
		cache.store.RecordFailure(descendant, netip.Prefix{}, FailureProvenance("test"))
		got := nxCutExchange(t, cache, downstream, descendant, "192.0.2.5:53000")
		assertNXCutResponse(t, got, descendant)
		if ede := dnsutil.GetEDE(got); ede != nil && ede.InfoCode == dns.ExtendedErrorCodeCachedError {
			t.Fatalf("failure cache shadowed NXDOMAIN cut: EDE=%+v", ede)
		}
		if calls != 1 {
			t.Fatalf("cut/failure lookup reached downstream; calls = %d, want 1", calls)
		}
	})
}

type nxCutTerminalQueryer struct {
	deniedName string
	zone       string
	calls      int
}

func (q *nxCutTerminalQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q.calls++
	resp := nxCutValidatedResponse(req, q.deniedName, q.zone)
	nxCutMark(ctx, resp, q.deniedName, q.zone)
	return resp, nil
}

type nxCutPrefetchQueryer struct {
	deniedName string
	clearCD    bool
}

func (q *nxCutPrefetchQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := nxCutValidatedResponse(req, q.deniedName, nxCutZone)
	if q.clearCD {
		resp.CheckingDisabled = false
	}
	nxCutMark(ctx, resp, q.deniedName, nxCutZone)
	return resp, nil
}

func TestNXDomainCutIntegrationPrefetchAdmissionFollowsCAS(t *testing.T) {
	t.Run("successful refresh publishes cut", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		const denied = "prefetch.missing.secure.example."
		req := nxCutRequest(denied, dns.TypeA)
		key := CacheKey{Question: req.Question[0]}.Hash()
		entry := NewCacheEntryWithKey(nxCutPositiveResponse(req), time.Minute, 0, key)
		cache.positive.Set(key, entry)
		cache.SetPrefetchQueryer(&nxCutPrefetchQueryer{deniedName: denied})

		queue := NewPrefetchQueue(0, 1, cache.metrics)
		defer queue.Stop()
		queue.processPrefetch(PrefetchRequest{
			Request: req,
			Key:     key,
			Cache:   cache,
			Entry:   entry,
		})

		if got := cache.store.NXDomainCutLen(); got != 1 {
			t.Fatalf("successful authenticated refresh published %d cuts, want 1", got)
		}
	})

	t.Run("superseded refresh cannot publish cut", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		const denied = "stale-prefetch.missing.secure.example."
		req := nxCutRequest(denied, dns.TypeA)
		key := CacheKey{Question: req.Question[0]}.Hash()
		claimed := NewCacheEntryWithKey(nxCutPositiveResponse(req), time.Minute, 0, key)
		cache.positive.Set(key, claimed)
		// A newer generation wins before the asynchronous refresh returns.
		newer := NewCacheEntryWithKey(nxCutPositiveResponse(req), time.Minute, 0, key)
		cache.positive.Set(key, newer)
		cache.SetPrefetchQueryer(&nxCutPrefetchQueryer{deniedName: denied})

		queue := NewPrefetchQueue(0, 1, cache.metrics)
		defer queue.Stop()
		queue.processPrefetch(PrefetchRequest{
			Request: req,
			Key:     key,
			Cache:   cache,
			Entry:   claimed,
		})

		if got := cache.store.NXDomainCutLen(); got != 0 {
			t.Fatalf("stale refresh published %d cuts after losing CAS", got)
		}
		if current, ok := cache.positive.Get(key); !ok || current != newer {
			t.Fatal("stale refresh displaced the newer cache generation")
		}
	})

	t.Run("CD request cannot publish cut after response bit is cleared", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		const denied = "cd-prefetch.missing.secure.example."
		req := nxCutRequest(denied, dns.TypeA)
		req.CheckingDisabled = true
		key := CacheKey{Question: req.Question[0], CD: true}.Hash()
		entry := NewCacheEntryWithKey(nxCutPositiveResponse(req), time.Minute, 0, key)
		cache.positive.Set(key, entry)
		cache.SetPrefetchQueryer(&nxCutPrefetchQueryer{deniedName: denied, clearCD: true})

		queue := NewPrefetchQueue(0, 1, cache.metrics)
		defer queue.Stop()
		queue.processPrefetch(PrefetchRequest{
			Request: req,
			Key:     key,
			Cache:   cache,
			Entry:   entry,
		})

		if got := cache.store.NXDomainCutLen(); got != 0 {
			t.Fatalf("CD prefetch published %d cuts after response CD was cleared", got)
		}
	})

	t.Run("ECS request cannot publish shared cut from unscoped entry", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		const denied = "ecs-prefetch.missing.secure.example."
		req := nxCutRequestWithECS(denied, "203.0.113.0")
		key := CacheKey{Question: req.Question[0]}.Hash()
		entry := NewCacheEntryWithKey(nxCutPositiveResponse(req), time.Minute, 0, key)
		cache.positive.Set(key, entry)
		cache.SetPrefetchQueryer(&nxCutPrefetchQueryer{deniedName: denied})

		queue := NewPrefetchQueue(0, 1, cache.metrics)
		defer queue.Stop()
		queue.processPrefetch(PrefetchRequest{
			Request: req,
			Key:     key,
			Cache:   cache,
			Entry:   entry,
		})

		if got := cache.store.NXDomainCutLen(); got != 0 {
			t.Fatalf("ECS prefetch published %d shared cuts", got)
		}
	})
}

func TestNXDomainCutIntegrationCNAMETransfersTerminalProvenance(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	const (
		alias        = "alias.other.example."
		terminal     = "terminal.secure.example."
		terminalDesc = "child.terminal.secure.example."
	)
	targetQueryer := &nxCutTerminalQueryer{deniedName: terminal, zone: nxCutZone}
	cache.SetQueryer(targetQueryer)

	downstreamCalls := 0
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		downstreamCalls++
		if ch.Request.Question[0].Name == alias {
			resp := new(dns.Msg)
			resp.SetReply(ch.Request)
			resp.RecursionAvailable = true
			resp.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: alias, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: terminal,
			}}
			_ = ch.Writer.WriteMsg(resp)
			ch.Cancel()
			return
		}
		_ = ch.Writer.WriteMsg(nxCutPositiveResponse(ch.Request))
		ch.Cancel()
	})

	outer := nxCutRequest(alias, dns.TypeA)
	gotOuter := nxCutExchange(t, cache, downstream, outer, "192.0.2.6:53000")
	if gotOuter.Rcode != dns.RcodeNameError {
		t.Fatalf("CNAME terminal response rcode = %s, want NXDOMAIN", dns.RcodeToString[gotOuter.Rcode])
	}
	if targetQueryer.calls != 1 {
		t.Fatalf("terminal CNAME chase queries = %d, want 1", targetQueryer.calls)
	}
	if cache.store.NXDomainCutLen() != 1 {
		t.Fatalf("terminal CNAME provenance admitted %d cuts, want 1", cache.store.NXDomainCutLen())
	}

	descendant := nxCutRequest(terminalDesc, dns.TypeAAAA)
	gotDescendant := nxCutExchange(t, cache, downstream, descendant, "192.0.2.6:53000")
	assertNXCutResponse(t, gotDescendant, descendant)
	if targetQueryer.calls != 1 {
		t.Fatalf("terminal cut hit re-queried CNAME target; queries = %d", targetQueryer.calls)
	}
	if downstreamCalls != 1 {
		t.Fatalf("terminal cut hit reached outer downstream; calls = %d", downstreamCalls)
	}

	// The terminal denied target, not the original alias subtree, owns the
	// cut. A child of the alias therefore remains an ordinary miss.
	aliasChild := nxCutRequest("child."+alias, dns.TypeAAAA)
	gotAliasChild := nxCutExchange(t, cache, downstream, aliasChild, "192.0.2.6:53000")
	if gotAliasChild.Rcode != dns.RcodeSuccess || len(gotAliasChild.Answer) != 1 {
		t.Fatalf("alias subtree was incorrectly cut: rcode=%s answer=%v",
			dns.RcodeToString[gotAliasChild.Rcode], gotAliasChild.Answer)
	}
	if targetQueryer.calls != 1 {
		t.Fatalf("alias-child miss unexpectedly queried terminal target; queries = %d", targetQueryer.calls)
	}
}
