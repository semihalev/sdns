package cache

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

const (
	aggressiveNegativeZone   = "aggressive.example."
	aggressiveNegativeOwner  = "www.aggressive.example."
	aggressiveNegativeDenied = "m.aggressive.example."
)

func aggressiveNegativeRequest(name string, qtype uint16, do bool) *dns.Msg {
	req := denialProofTestRequest(name, qtype, do)
	req.RecursionDesired = true
	return req
}

func aggressiveNegativeRequestWithECS(name string, qtype uint16) *dns.Msg {
	req := aggressiveNegativeRequest(name, qtype, true)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("203.0.113.0").To4(),
	})
	return req
}

func aggressiveNegativeExchange(
	t *testing.T,
	ctx context.Context,
	cache *Cache,
	downstream middleware.Handler,
	req *dns.Msg,
) *dns.Msg {
	t.Helper()
	writer := mock.NewWriter("udp", "192.0.2.53:53000")
	chain := middleware.NewChain([]middleware.Handler{cache, downstream})
	chain.Reset(writer, req)
	chain.Next(ctx)
	if !writer.Written() {
		t.Fatal("cache pipeline wrote no response")
	}
	return writer.Msg()
}

func aggressiveNegativeMark(
	ctx context.Context,
	resp *dns.Msg,
	subject string,
	kind middleware.ValidatedNegativeProofKind,
) {
	middleware.MarkValidatedNegativeProofResponse(ctx, resp, middleware.ValidatedNegativeProof{
		Subject:    subject,
		Zone:       aggressiveNegativeZone,
		Kind:       kind,
		Aggressive: true,
	})
}

func aggressiveNegativeMakeSignaturesPackable(msg *dns.Msg) {
	for _, rr := range msg.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sig.Signature = "AA=="
		}
	}
}

func aggressiveNegativePositiveResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	q := req.Question[0]

	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name: q.Name, Rrtype: dns.TypeA, Class: q.Qclass, Ttl: 300,
			},
			A: net.ParseIP("192.0.2.80").To4(),
		}}
	case dns.TypeAAAA:
		resp.Answer = []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name: q.Name, Rrtype: dns.TypeAAAA, Class: q.Qclass, Ttl: 300,
			},
			AAAA: net.ParseIP("2001:db8::80"),
		}}
	case dns.TypeMX:
		resp.Answer = []dns.RR{&dns.MX{
			Hdr: dns.RR_Header{
				Name: q.Name, Rrtype: dns.TypeMX, Class: q.Qclass, Ttl: 300,
			},
			Preference: 10,
			Mx:         "mail.aggressive.example.",
		}}
	case dns.TypeSRV:
		resp.Answer = []dns.RR{&dns.SRV{
			Hdr: dns.RR_Header{
				Name: q.Name, Rrtype: dns.TypeSRV, Class: q.Qclass, Ttl: 300,
			},
			Port:   443,
			Target: "service.aggressive.example.",
		}}
	default:
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{
				Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass, Ttl: 300,
			},
			Txt: []string{"downstream"},
		}}
	}
	return resp
}

func aggressiveNegativeNSECResponse(
	t *testing.T,
	ctx context.Context,
	req *dns.Msg,
	rcode int,
	intervals ...[2]string,
) *dns.Msg {
	t.Helper()
	fixture := newDenialProofNSECFixture(
		t,
		time.Now().UTC(),
		req.Question[0].Name,
		req.Question[0].Qtype,
		rcode,
		aggressiveNegativeZone,
		intervals...,
	)
	fixture.msg.Id = req.Id
	fixture.msg.RecursionDesired = req.RecursionDesired
	fixture.msg.CheckingDisabled = req.CheckingDisabled
	fixture.msg.RecursionAvailable = true
	aggressiveNegativeMakeSignaturesPackable(fixture.msg)
	aggressiveNegativeMark(
		ctx,
		fixture.msg,
		req.Question[0].Name,
		middleware.ValidatedNegativeProofNSEC,
	)
	return fixture.msg
}

func aggressiveNegativeNSEC3Response(
	t *testing.T,
	ctx context.Context,
	req *dns.Msg,
) *dns.Msg {
	t.Helper()
	fixture := newDenialProofNSEC3Fixture(
		t,
		time.Now().UTC(),
		req.Question[0].Name,
		aggressiveNegativeZone,
		"CAFE",
		0,
		1,
	)
	fixture.msg.Id = req.Id
	fixture.msg.RecursionDesired = req.RecursionDesired
	fixture.msg.CheckingDisabled = req.CheckingDisabled
	fixture.msg.RecursionAvailable = true
	aggressiveNegativeMakeSignaturesPackable(fixture.msg)
	aggressiveNegativeMark(
		ctx,
		fixture.msg,
		req.Question[0].Name,
		middleware.ValidatedNegativeProofNSEC3,
	)
	return fixture.msg
}

func assertAggressiveNegativeProof(
	t *testing.T,
	resp, req *dns.Msg,
	rcode int,
	proofType uint16,
) {
	t.Helper()
	if resp.Rcode != rcode {
		t.Fatalf("rcode = %s, want %s",
			dns.RcodeToString[resp.Rcode],
			dns.RcodeToString[rcode],
		)
	}
	if resp.Id != req.Id ||
		len(resp.Question) != 1 ||
		resp.Question[0] != req.Question[0] ||
		len(resp.Answer) != 0 ||
		!resp.AuthenticatedData {
		t.Fatalf("malformed aggressive response: %#v", resp)
	}
	if denialProofCountType(resp.Ns, dns.TypeSOA) != 1 ||
		denialProofCountType(resp.Ns, proofType) == 0 ||
		denialProofCountType(resp.Ns, dns.TypeRRSIG) < 2 {
		t.Fatalf("authority lacks complete selected proof: %v", resp.Ns)
	}
}

func TestAggressiveNegativeIntegrationRequiresExplicitProvenance(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	calls := 0
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		calls++
		if ch.Request.Msg().Question[0].Qtype == dns.TypeAAAA {
			// AD=1 and proof-shaped authority data are intentionally
			// insufficient. Only the resolver-local pointer-identity mark may
			// publish material into the shared RFC 8198 index.
			fixture := newDenialProofNSECFixture(
				t,
				time.Now().UTC(),
				aggressiveNegativeOwner,
				dns.TypeAAAA,
				dns.RcodeSuccess,
				aggressiveNegativeZone,
				[2]string{aggressiveNegativeOwner, "z." + aggressiveNegativeZone},
			)
			aggressiveNegativeMakeSignaturesPackable(fixture.msg)
			_ = ch.Writer.WriteMsg(fixture.msg)
			ch.Cancel()
			return
		}
		_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
		ch.Cancel()
	})

	seed := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeAAAA, true)
	if got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed); got.Rcode != dns.RcodeSuccess {
		t.Fatalf("seed rcode = %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}
	if got := cache.store.DenialProofLen(); got != 0 {
		t.Fatalf("unmarked AD response admitted %d proof entries", got)
	}

	probe := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeMX, true)
	got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, probe)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("unmarked proof synthesized a response: rcode=%s answer=%v",
			dns.RcodeToString[got.Rcode],
			got.Answer,
		)
	}
	if calls != 2 {
		t.Fatalf("downstream calls = %d, want seed + probe", calls)
	}
}

func TestAggressiveNegativeIntegrationNODATAAndNXDOMAIN(t *testing.T) {
	t.Run("NODATA precedes shared failure state", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			_ = ch.Writer.WriteMsg(aggressiveNegativeNSECResponse(
				t,
				ctx,
				ch.Request.Msg(),
				dns.RcodeSuccess,
				[2]string{aggressiveNegativeOwner, "z." + aggressiveNegativeZone},
			))
			ch.Cancel()
		})

		seed := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeAAAA, true)
		_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
		if cache.store.DenialProofLen() == 0 {
			t.Fatal("validated NODATA did not publish denial proof material")
		}

		probe := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeMX, true)
		cache.store.RecordFailure(probe, netip.Prefix{}, FailureProvenance("test"), nil)
		got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, probe)
		assertAggressiveNegativeProof(t, got, probe, dns.RcodeSuccess, dns.TypeNSEC)
		if calls != 1 {
			t.Fatalf("NODATA synthesis reached downstream; calls = %d, want 1", calls)
		}
	})

	t.Run("NXDOMAIN sibling is synthesized outside the RFC 8020 cut", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			_ = ch.Writer.WriteMsg(aggressiveNegativeNSECResponse(
				t,
				ctx,
				ch.Request.Msg(),
				dns.RcodeNameError,
				[2]string{"a." + aggressiveNegativeZone, "z." + aggressiveNegativeZone},
				[2]string{aggressiveNegativeZone, "a." + aggressiveNegativeZone},
			))
			ch.Cancel()
		})

		seed := aggressiveNegativeRequest(aggressiveNegativeDenied, dns.TypeA, true)
		_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
		if cache.store.DenialProofLen() == 0 {
			t.Fatal("validated NXDOMAIN did not publish denial proof material")
		}

		// n.* is a sibling of the denied m.* name, so the RFC 8020 subtree
		// cut cannot answer it. The retained NSEC intervals can.
		probe := aggressiveNegativeRequest("n."+aggressiveNegativeZone, dns.TypeAAAA, true)
		got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, probe)
		assertAggressiveNegativeProof(t, got, probe, dns.RcodeNameError, dns.TypeNSEC)
		if calls != 1 {
			t.Fatalf("NXDOMAIN synthesis reached downstream; calls = %d, want 1", calls)
		}
	})
}

func TestAggressiveNegativeIntegrationCDAndRawECSBypass(t *testing.T) {
	t.Run("lookup bypasses retained shared proof", func(t *testing.T) {
		cache := New(&config.Config{CacheSize: 1024, Expire: 300})
		defer cache.Stop()

		calls := 0
		downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			calls++
			if ch.Request.Msg().Question[0].Qtype == dns.TypeAAAA {
				_ = ch.Writer.WriteMsg(aggressiveNegativeNSECResponse(
					t,
					ctx,
					ch.Request.Msg(),
					dns.RcodeSuccess,
					[2]string{aggressiveNegativeOwner, "z." + aggressiveNegativeZone},
				))
				ch.Cancel()
				return
			}
			_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
			ch.Cancel()
		})

		_ = aggressiveNegativeExchange(
			t,
			context.Background(),
			cache,
			downstream,
			aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeAAAA, true),
		)

		cd := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeMX, true)
		cd.CheckingDisabled = true
		if got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, cd); len(got.Answer) != 1 {
			t.Fatalf("CD=1 request consumed shared proof: %#v", got)
		}

		ecs := aggressiveNegativeRequestWithECS(
			aggressiveNegativeOwner,
			dns.TypeTXT,
		)
		if got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, ecs); len(got.Answer) != 1 {
			t.Fatalf("raw ECS request consumed shared proof: %#v", got)
		}

		normal := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeSRV, true)
		assertAggressiveNegativeProof(
			t,
			aggressiveNegativeExchange(t, context.Background(), cache, downstream, normal),
			normal,
			dns.RcodeSuccess,
			dns.TypeNSEC,
		)
		if calls != 3 {
			t.Fatalf("downstream calls = %d, want seed + CD + ECS", calls)
		}
	})

	for _, test := range []struct {
		name string
		seed func(*dns.Msg)
	}{
		{
			name: "CD seed",
			seed: func(req *dns.Msg) {
				req.CheckingDisabled = true
			},
		},
		{
			name: "raw ECS seed",
			seed: func(req *dns.Msg) {
				opt := req.IsEdns0()
				opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        1,
					SourceNetmask: 24,
					Address:       net.ParseIP("203.0.113.0").To4(),
				})
			},
		},
	} {
		t.Run(test.name+" cannot publish", func(t *testing.T) {
			cache := New(&config.Config{CacheSize: 1024, Expire: 300})
			defer cache.Stop()

			calls := 0
			downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
				calls++
				if ch.Request.Msg().Question[0].Qtype == dns.TypeAAAA {
					resp := aggressiveNegativeNSECResponse(
						t,
						ctx,
						ch.Request.Msg(),
						dns.RcodeSuccess,
						[2]string{aggressiveNegativeOwner, "z." + aggressiveNegativeZone},
					)
					// Exercise the immutable request snapshot: downstream
					// response shaping cannot turn a CD=1 seed into an
					// admissible shared proof.
					resp.CheckingDisabled = false
					_ = ch.Writer.WriteMsg(resp)
					ch.Cancel()
					return
				}
				_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
				ch.Cancel()
			})

			seed := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeAAAA, true)
			test.seed(seed)
			_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
			if got := cache.store.DenialProofLen(); got != 0 {
				t.Fatalf("scoped/checking-disabled seed admitted %d proof entries", got)
			}

			probe := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeMX, true)
			if got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, probe); len(got.Answer) != 1 {
				t.Fatalf("unscoped probe consumed forbidden proof: %#v", got)
			}
			if calls != 2 {
				t.Fatalf("downstream calls = %d, want seed + probe", calls)
			}
		})
	}
}

func TestAggressiveNegativeIntegrationNSEC3LimiterSaturationFailsOpen(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	limiter := dnssec.NewCryptoLimiter(1)
	cache.SetDNSSECCryptoLimiter(limiter)

	calls := 0
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		calls++
		if ch.Request.Msg().Question[0].Qtype == dns.TypeAAAA {
			_ = ch.Writer.WriteMsg(aggressiveNegativeNSEC3Response(t, ctx, ch.Request.Msg()))
			ch.Cancel()
			return
		}
		_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
		ch.Cancel()
	})

	seed := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeAAAA, true)
	_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
	if cache.store.DenialProofLen() == 0 {
		t.Fatal("validated NSEC3 NODATA did not publish proof material")
	}

	heldRelease, ok := limiter.TryAcquire()
	if !ok {
		t.Fatal("failed to occupy the only shared crypto slot")
	}
	saturated := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeMX, true)
	got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, saturated)
	heldRelease()
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("saturated optional lookup leaked a client error: rcode=%s answer=%v",
			dns.RcodeToString[got.Rcode],
			got.Answer,
		)
	}

	available := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeTXT, true)
	assertAggressiveNegativeProof(
		t,
		aggressiveNegativeExchange(t, context.Background(), cache, downstream, available),
		available,
		dns.RcodeSuccess,
		dns.TypeNSEC3,
	)
	if calls != 2 {
		t.Fatalf("downstream calls = %d, want seed + saturated fallback", calls)
	}
}

func TestAggressiveNegativeIntegrationDO0StripsDNSSECAndMarksMetadata(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	calls := 0
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		calls++
		_ = ch.Writer.WriteMsg(aggressiveNegativeNSECResponse(
			t,
			ctx,
			ch.Request.Msg(),
			dns.RcodeSuccess,
			[2]string{aggressiveNegativeOwner, "z." + aggressiveNegativeZone},
		))
		ch.Cancel()
	})

	seed := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeAAAA, true)
	_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)

	var meta middleware.ResponseMeta
	hitCtx := middleware.WithResponseMeta(context.Background(), &meta)
	probe := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeMX, false)
	got := aggressiveNegativeExchange(t, hitCtx, cache, downstream, probe)
	if got.Rcode != dns.RcodeSuccess ||
		!got.AuthenticatedData ||
		len(got.Answer) != 0 ||
		denialProofCountType(got.Ns, dns.TypeSOA) != 1 ||
		denialProofCountType(got.Ns, dns.TypeNSEC) != 0 ||
		denialProofCountType(got.Ns, dns.TypeNSEC3) != 0 ||
		denialProofCountType(got.Ns, dns.TypeRRSIG) != 0 {
		t.Fatalf("DO=0 synthesis leaked DNSSEC material or lost denial shape: %#v", got)
	}

	negative, ok := middleware.ValidatedNegativeProofForResponse(hitCtx, got)
	if !ok ||
		negative.Subject != aggressiveNegativeOwner ||
		negative.Zone != aggressiveNegativeZone ||
		negative.Kind != middleware.ValidatedNegativeProofNSEC ||
		!negative.Aggressive ||
		negative.Proof != got {
		t.Fatalf("DO=0 synthesized response metadata = %#v, %v", negative, ok)
	}
	if calls != 1 {
		t.Fatalf("DO=0 synthesis reached downstream; calls = %d, want 1", calls)
	}
}

type aggressiveNegativeChainQueryer struct {
	handlers []middleware.Handler
}

func (q *aggressiveNegativeChainQueryer) Query(
	ctx context.Context,
	req *dns.Msg,
) (*dns.Msg, error) {
	writer := mock.NewWriter("tcp", "127.0.0.255:0")
	chain := middleware.NewChain(q.handlers)
	chain.Reset(writer, req)
	chain.Next(ctx)
	if !writer.Written() {
		return nil, middleware.ErrNoResponse
	}
	return writer.Msg(), nil
}

func TestAggressiveNegativeIntegrationOuterECSBypassesAliasTargetProof(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	const (
		alias  = "alias.other.example."
		target = "target.aggressive.example."
	)
	var seedCalls, aliasCalls, targetCalls int
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		q := ch.Request.Msg().Question[0]
		switch {
		case q.Name == target && q.Qtype == dns.TypeAAAA:
			seedCalls++
			_ = ch.Writer.WriteMsg(aggressiveNegativeNSECResponse(
				t,
				ctx,
				ch.Request.Msg(),
				dns.RcodeSuccess,
				[2]string{target, "z." + aggressiveNegativeZone},
			))
		case q.Name == alias:
			aliasCalls++
			resp := new(dns.Msg)
			resp.SetReply(ch.Request.Msg())
			resp.RecursionAvailable = true
			resp.Answer = []dns.RR{&dns.CNAME{
				Hdr: dns.RR_Header{
					Name: alias, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300,
				},
				Target: target,
			}}
			_ = ch.Writer.WriteMsg(resp)
		case q.Name == target:
			targetCalls++
			_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
		default:
			t.Fatalf("unexpected downstream question: %v", q)
		}
		ch.Cancel()
	})

	seed := aggressiveNegativeRequest(target, dns.TypeAAAA, true)
	_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
	if cache.store.DenialProofLen() == 0 {
		t.Fatal("target NODATA proof was not retained")
	}

	cache.SetQueryer(&aggressiveNegativeChainQueryer{
		handlers: []middleware.Handler{cache, downstream},
	})
	outer := aggressiveNegativeRequestWithECS(alias, dns.TypeMX)
	got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, outer)
	if got.Rcode != dns.RcodeSuccess {
		t.Fatalf("outer alias rcode = %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}
	if denialProofCountType(got.Answer, dns.TypeCNAME) != 1 ||
		denialProofCountType(got.Answer, dns.TypeMX) != 1 {
		t.Fatalf("outer ECS alias did not receive target fallback answer: %v", got.Answer)
	}
	if len(got.Ns) != 0 {
		t.Fatalf("outer ECS alias consumed shared target denial: %v", got.Ns)
	}
	if seedCalls != 1 || aliasCalls != 1 || targetCalls != 1 {
		t.Fatalf("downstream calls = seed %d alias %d target %d, want 1/1/1",
			seedCalls,
			aliasCalls,
			targetCalls,
		)
	}
}

func TestAggressiveNegativeIntegrationOuterCDBypassesAliasTargetProof(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	const (
		alias  = "alias.cd.example."
		target = "target.aggressive.example."
	)
	var seedCalls, aliasCalls, targetCalls int
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		q := ch.Request.Msg().Question[0]
		switch {
		case q.Name == target && q.Qtype == dns.TypeAAAA:
			seedCalls++
			_ = ch.Writer.WriteMsg(aggressiveNegativeNSECResponse(
				t,
				ctx,
				ch.Request.Msg(),
				dns.RcodeSuccess,
				[2]string{target, "z." + aggressiveNegativeZone},
			))
		case q.Name == alias:
			aliasCalls++
			resp := new(dns.Msg)
			resp.SetReply(ch.Request.Msg())
			// Simulate a non-conforming upstream or intervening response
			// writer clearing CD. The incoming client bit remains pinned in
			// the request-tree context and must govern the target lookup.
			resp.CheckingDisabled = false
			resp.RecursionAvailable = true
			resp.Answer = []dns.RR{&dns.CNAME{
				Hdr: dns.RR_Header{
					Name: alias, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300,
				},
				Target: target,
			}}
			_ = ch.Writer.WriteMsg(resp)
		case q.Name == target:
			targetCalls++
			_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
		default:
			t.Fatalf("unexpected downstream question: %v", q)
		}
		ch.Cancel()
	})

	seed := aggressiveNegativeRequest(target, dns.TypeAAAA, true)
	_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
	if cache.store.DenialProofLen() == 0 {
		t.Fatal("target NODATA proof was not retained")
	}

	cache.SetQueryer(&aggressiveNegativeChainQueryer{
		handlers: []middleware.Handler{cache, downstream},
	})
	outer := aggressiveNegativeRequest(alias, dns.TypeMX, true)
	outer.CheckingDisabled = true
	got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, outer)
	if got.Rcode != dns.RcodeSuccess {
		t.Fatalf("outer alias rcode = %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}
	if denialProofCountType(got.Answer, dns.TypeCNAME) != 1 ||
		denialProofCountType(got.Answer, dns.TypeMX) != 1 {
		t.Fatalf("outer CD alias did not receive target fallback answer: %v", got.Answer)
	}
	if len(got.Ns) != 0 {
		t.Fatalf("outer CD alias consumed shared target denial: %v", got.Ns)
	}
	if seedCalls != 1 || aliasCalls != 1 || targetCalls != 1 {
		t.Fatalf("downstream calls = seed %d alias %d target %d, want 1/1/1",
			seedCalls,
			aliasCalls,
			targetCalls,
		)
	}
}
