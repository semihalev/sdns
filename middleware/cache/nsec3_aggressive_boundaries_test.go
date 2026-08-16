package cache

import (
	"context"
	"encoding/base32"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

const (
	p6NSEC3Zone   = "p6.example."
	p6NSEC3Denied = "missing.p6.example."
)

var (
	p6NSEC3Base32 = base32.HexEncoding.WithPadding(base32.NoPadding)
	errP6Budget   = errors.New("p6 NSEC3 request budget exhausted")
)

func p6AdjacentNSEC3Hash(t testing.TB, encoded string, delta int) string {
	t.Helper()
	value, err := p6NSEC3Base32.DecodeString(strings.ToUpper(encoded))
	if err != nil || len(value) != 20 {
		t.Fatalf("decode NSEC3 hash %q: length=%d err=%v", encoded, len(value), err)
	}

	switch delta {
	case 1:
		for index := len(value) - 1; index >= 0; index-- {
			value[index]++
			if value[index] != 0 {
				break
			}
		}
	case -1:
		for index := len(value) - 1; index >= 0; index-- {
			previous := value[index]
			value[index]--
			if previous != 0 {
				break
			}
		}
	default:
		t.Fatalf("unsupported NSEC3 adjacency delta %d", delta)
	}
	return p6NSEC3Base32.EncodeToString(value)
}

func p6NSEC3Record(
	zone, ownerHash, nextHash string,
	flags uint8,
	bitmap []uint16,
) *dns.NSEC3 {
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   ownerHash + "." + dns.Fqdn(zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: append([]uint16(nil), bitmap...),
	}
}

func p6PackableSignature(
	owner string,
	covered uint16,
	zone string,
	expiration uint32,
) *dns.RRSIG {
	sig := denialProofTestSignature(
		owner,
		covered,
		zone,
		dns.ClassINET,
		300,
		expiration,
	)
	sig.Signature = "AA=="
	return sig
}

func newP6NSEC3NXDOMAINFixture(
	t testing.TB,
	now time.Time,
	qname string,
) *denialProofTestFixture {
	t.Helper()
	qname = dns.Fqdn(qname)
	zone := dns.Fqdn(p6NSEC3Zone)
	expiration := uint32(now.Add(2 * time.Hour).Unix()) //nolint:gosec // fixed DNSSEC test epoch

	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	msg := new(dns.Msg)
	msg.SetRcode(req, dns.RcodeNameError)
	msg.AuthenticatedData = true
	msg.RecursionAvailable = true

	soa := denialProofTestSOA(zone, 300)
	soaSig := p6PackableSignature(zone, dns.TypeSOA, zone, expiration)

	closestHash := dns.HashName(zone, dns.SHA1, 0, "")
	qnameHash := dns.HashName(qname, dns.SHA1, 0, "")
	wildcardHash := dns.HashName("*."+zone, dns.SHA1, 0, "")
	if closestHash == qnameHash || closestHash == wildcardHash || qnameHash == wildcardHash {
		t.Fatal("fixture unexpectedly produced an NSEC3 hash collision")
	}

	proofs := []*dns.NSEC3{
		p6NSEC3Record(
			zone,
			closestHash,
			p6AdjacentNSEC3Hash(t, closestHash, 1),
			0,
			[]uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC3},
		),
		p6NSEC3Record(
			zone,
			p6AdjacentNSEC3Hash(t, qnameHash, -1),
			p6AdjacentNSEC3Hash(t, qnameHash, 1),
			0,
			[]uint16{dns.TypeRRSIG, dns.TypeNSEC3},
		),
		p6NSEC3Record(
			zone,
			p6AdjacentNSEC3Hash(t, wildcardHash, -1),
			p6AdjacentNSEC3Hash(t, wildcardHash, 1),
			0,
			[]uint16{dns.TypeRRSIG, dns.TypeNSEC3},
		),
	}

	fixture := &denialProofTestFixture{
		msg:    msg,
		soa:    soa,
		soaSig: soaSig,
	}
	msg.Ns = append(msg.Ns, soa, soaSig)
	for _, proof := range proofs {
		sig := p6PackableSignature(
			proof.Hdr.Name,
			dns.TypeNSEC3,
			zone,
			expiration,
		)
		fixture.proofs = append(fixture.proofs, proof)
		fixture.proofSigs = append(fixture.proofSigs, sig)
		msg.Ns = append(msg.Ns, proof, sig)
	}
	return fixture
}

func p6PartialNSEC3Fixture(
	fixture *denialProofTestFixture,
	proofIndexes ...int,
) *dns.Msg {
	msg := fixture.msg.Copy()
	msg.Ns = []dns.RR{
		dns.Copy(fixture.soa),
		dns.Copy(fixture.soaSig),
	}
	for _, index := range proofIndexes {
		msg.Ns = append(
			msg.Ns,
			dns.Copy(fixture.proofs[index]),
			dns.Copy(fixture.proofSigs[index]),
		)
	}
	return msg
}

type p6NSEC3Work struct {
	limit    int
	calls    int
	attempts int
}

func (w *p6NSEC3Work) BeginNSEC3Hash() (func(), error) {
	w.attempts++
	if w.calls >= w.limit {
		return nil, errP6Budget
	}
	w.calls++
	return func() {}, nil
}

type p6CountingCryptoLimiter struct {
	calls   atomic.Int32
	allowed atomic.Int32
}

func newP6CountingCryptoLimiter(allowed int32) *p6CountingCryptoLimiter {
	limiter := new(p6CountingCryptoLimiter)
	limiter.allowed.Store(allowed)
	return limiter
}

func (l *p6CountingCryptoLimiter) TryAcquire() (func(), bool) {
	call := l.calls.Add(1)
	if call > l.allowed.Load() {
		return nil, false
	}
	return func() {}, true
}

func (l *p6CountingCryptoLimiter) reset(allowed int32) {
	l.calls.Store(0)
	l.allowed.Store(allowed)
}

func TestP6NSEC3ValidNODATAAndNXDOMAINSynthesis(t *testing.T) {
	t.Run("exact NODATA including an Opt-Out-marked exact owner", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			flags uint8
		}{
			{name: "ordinary exact owner", flags: 0},
			{name: "Opt-Out flag on exact owner", flags: 1},
		} {
			t.Run(test.name, func(t *testing.T) {
				now := time.Now().UTC()
				fixture := newDenialProofNSEC3Fixture(
					t,
					now,
					"host."+p6NSEC3Zone,
					p6NSEC3Zone,
					"CAFE",
					test.flags,
					1,
				)
				cache := newDenialProofTestCache(&now, 16, 8, maxDenialProofTTL)
				if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
					t.Fatal("valid exact NSEC3 NODATA proof was not admitted")
				}

				work := &p6NSEC3Work{limit: 1}
				req := denialProofTestRequest(
					"host."+p6NSEC3Zone,
					dns.TypeAAAA,
					true,
				)
				got, ok := cache.Lookup(req, work)
				if !ok || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 0 {
					t.Fatalf("exact NSEC3 NODATA = %#v, hit=%v", got, ok)
				}
				if denialProofCountType(got.Ns, dns.TypeNSEC3) != 1 ||
					denialProofCountType(got.Ns, dns.TypeRRSIG) != 2 {
					t.Fatalf("exact NODATA proof shape = %v", got.Ns)
				}
				if work.calls != 1 || work.attempts != 1 {
					t.Fatalf("exact NODATA hashes = calls %d attempts %d, want 1/1",
						work.calls,
						work.attempts,
					)
				}
			})
		}
	})

	t.Run("closest-encloser NXDOMAIN", func(t *testing.T) {
		now := time.Now().UTC()
		fixture := newP6NSEC3NXDOMAINFixture(t, now, p6NSEC3Denied)
		cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
		if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
			t.Fatal("valid NSEC3 NXDOMAIN proof was not admitted")
		}

		work := &p6NSEC3Work{limit: 3}
		req := denialProofTestRequest(p6NSEC3Denied, dns.TypeAAAA, true)
		got, ok := cache.Lookup(req, work)
		if !ok || got.Rcode != dns.RcodeNameError || len(got.Answer) != 0 {
			t.Fatalf("NSEC3 NXDOMAIN = %#v, hit=%v", got, ok)
		}
		if denialProofCountType(got.Ns, dns.TypeNSEC3) != 3 ||
			denialProofCountType(got.Ns, dns.TypeRRSIG) != 4 {
			t.Fatalf("NXDOMAIN did not retain its exact witnesses: %v", got.Ns)
		}
		if work.calls != 3 || work.attempts != 3 {
			t.Fatalf("NXDOMAIN hashes = calls %d attempts %d, want 3 unique names",
				work.calls,
				work.attempts,
			)
		}
	})
}

func TestP6NSEC3OptOutCoveringRecordsFailOpen(t *testing.T) {
	for _, proofIndex := range []int{1, 2} {
		name := "next-closer"
		if proofIndex == 2 {
			name = "wildcard"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			fixture := newP6NSEC3NXDOMAINFixture(t, now, p6NSEC3Denied)
			fixture.proofs[proofIndex].(*dns.NSEC3).Flags = 1
			cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
			if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
				t.Fatal("structurally valid Opt-Out proof should be retained for other safe uses")
			}

			req := denialProofTestRequest(p6NSEC3Denied, dns.TypeA, true)
			if got, ok := cache.Lookup(req, &p6NSEC3Work{limit: 8}); ok || got != nil {
				t.Fatalf("Opt-Out covering record synthesized NXDOMAIN: %#v", got)
			}
			if cache.len() != 4 {
				t.Fatalf("fail-open lookup mutated retained proof count: got %d, want 4", cache.len())
			}
		})
	}
}

func TestP6NSEC3ParameterGroupsNeverCombine(t *testing.T) {
	now := time.Now().UTC()
	fixture := newP6NSEC3NXDOMAINFixture(t, now, p6NSEC3Denied)
	cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)

	// The first tuple has closest-encloser and next-closer proof but no
	// wildcard denial. The second tuple has only a wildcard interval. Neither
	// tuple is independently complete, so combining them would be unsafe.
	firstTuple := p6PartialNSEC3Fixture(fixture, 0, 1)
	secondTuple := p6PartialNSEC3Fixture(fixture, 2)
	for _, rr := range secondTuple.Ns {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3.Salt = "AA"
			nsec3.SaltLength = 1
		}
	}
	if !cache.record(firstTuple, p6NSEC3Zone, time.Time{}) {
		t.Fatal("first independently signed partial tuple was not retained")
	}
	if !cache.record(secondTuple, p6NSEC3Zone, time.Time{}) {
		t.Fatal("second independently signed partial tuple was not retained")
	}

	req := denialProofTestRequest(p6NSEC3Denied, dns.TypeA, true)
	if got, ok := cache.Lookup(req, nil); ok || got != nil {
		t.Fatalf("records from different NSEC3 parameter tuples were combined: %#v", got)
	}
}

func TestP6NSEC3RejectsUnknownAlgorithmMixedTupleAndOwnerCollision(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(testing.TB, *denialProofTestFixture)
	}{
		{
			name: "unknown hash algorithm",
			mutate: func(_ testing.TB, fixture *denialProofTestFixture) {
				fixture.proofs[0].(*dns.NSEC3).Hash = 2
			},
		},
		{
			name: "mixed parameters in one response",
			mutate: func(tb testing.TB, fixture *denialProofTestFixture) {
				other := newDenialProofNSEC3Fixture(
					tb,
					time.Now().UTC(),
					"host."+p6NSEC3Zone,
					p6NSEC3Zone,
					"AA",
					0,
					0,
				)
				fixture.msg.Ns = append(
					fixture.msg.Ns,
					other.proofs[0],
					other.proofSigs[0],
				)
			},
		},
		{
			name: "conflicting records for one owner hash",
			mutate: func(tb testing.TB, fixture *denialProofTestFixture) {
				original := fixture.proofs[0].(*dns.NSEC3)
				conflict := dns.Copy(original).(*dns.NSEC3)
				ownerHash := dns.SplitDomainName(original.Hdr.Name)[0]
				conflict.NextDomain = p6AdjacentNSEC3Hash(tb, ownerHash, 1)
				fixture.msg.Ns = append(
					fixture.msg.Ns,
					conflict,
					dns.Copy(fixture.proofSigs[0]),
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			fixture := newDenialProofNSEC3Fixture(
				t,
				now,
				"host."+p6NSEC3Zone,
				p6NSEC3Zone,
				"",
				0,
				0,
			)
			test.mutate(t, fixture)
			cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
			if cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
				t.Fatal("unsafe NSEC3 set was admitted")
			}
			if cache.len() != 0 || cache.zones() != 0 || cache.bytes() != 0 {
				t.Fatalf("rejected NSEC3 set changed cache: len=%d zones=%d bytes=%d",
					cache.len(),
					cache.zones(),
					cache.bytes(),
				)
			}
		})
	}
}

func TestP6NSEC3RequestMemoAndBudgetFallback(t *testing.T) {
	now := time.Now().UTC()
	fixture := newP6NSEC3NXDOMAINFixture(t, now, p6NSEC3Denied)
	cache := newDenialProofTestCache(&now, 32, 16, maxDenialProofTTL)
	if !cache.record(fixture.msg, p6NSEC3Zone, time.Time{}) {
		t.Fatal("valid NXDOMAIN proof was not admitted")
	}
	req := denialProofTestRequest(p6NSEC3Denied, dns.TypeA, true)

	limited := &p6NSEC3Work{limit: 2}
	if got, ok := cache.Lookup(req, limited); ok || got != nil {
		t.Fatalf("budget-exhausted lookup synthesized a response: %#v", got)
	}
	if limited.calls != 2 || limited.attempts != 3 {
		t.Fatalf("limited request work = calls %d attempts %d, want 2/3",
			limited.calls,
			limited.attempts,
		)
	}

	// The failed request cannot poison the retained proof or share a partial
	// memo with the next request. Re-evaluation starts fresh and performs only
	// the three unique hashes (QNAME is reused as next-closer from the memo).
	complete := &p6NSEC3Work{limit: 3}
	got, ok := cache.Lookup(req, complete)
	if !ok || got.Rcode != dns.RcodeNameError {
		t.Fatalf("fresh request after budget fallback = %#v, hit=%v", got, ok)
	}
	if complete.calls != 3 || complete.attempts != 3 {
		t.Fatalf("fresh request work = calls %d attempts %d, want memoized 3/3",
			complete.calls,
			complete.attempts,
		)
	}
}

func TestP6NSEC3BudgetMissFallsThroughWithoutClientError(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	now := time.Now().UTC()
	fixture := newP6NSEC3NXDOMAINFixture(t, now, p6NSEC3Denied)
	if !cache.store.RecordDenialProof(
		fixture.msg,
		p6NSEC3Zone,
		middleware.ValidatedNegativeProofNSEC3,
		time.Time{},
	) {
		t.Fatal("valid NSEC3 proof was not installed")
	}

	limiter := newP6CountingCryptoLimiter(2)
	cache.SetDNSSECCryptoLimiter(limiter)
	downstreamCalls := 0
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		downstreamCalls++
		_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
		ch.Cancel()
	})

	fallback := aggressiveNegativeRequest(p6NSEC3Denied, dns.TypeA, true)
	got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, fallback)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("partial-budget miss leaked a client error: rcode=%s answer=%v",
			dns.RcodeToString[got.Rcode],
			got.Answer,
		)
	}
	if limiter.calls.Load() != 3 {
		t.Fatalf("partial-budget limiter calls = %d, want failure on third unique hash",
			limiter.calls.Load(),
		)
	}

	limiter.reset(3)
	available := aggressiveNegativeRequest(p6NSEC3Denied, dns.TypeAAAA, true)
	got = aggressiveNegativeExchange(t, context.Background(), cache, downstream, available)
	assertAggressiveNegativeProof(t, got, available, dns.RcodeNameError, dns.TypeNSEC3)
	if limiter.calls.Load() != 3 {
		t.Fatalf("available lookup hashes = %d, want 3", limiter.calls.Load())
	}
	if downstreamCalls != 1 {
		t.Fatalf("downstream calls = %d, want budget fallback only", downstreamCalls)
	}
}

func TestP6NSEC3CDAndECSBypassBeforeHashing(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	limiter := newP6CountingCryptoLimiter(8)
	cache.SetDNSSECCryptoLimiter(limiter)
	downstreamCalls := 0
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		downstreamCalls++
		if ch.Request.Msg().Question[0].Qtype == dns.TypeTXT &&
			!middleware.HasClientECS(ctx) {
			t.Error("cache-only raw ECS request lost the central tree marker")
		}
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

	cd := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeMX, true)
	cd.CheckingDisabled = true
	if got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, cd); len(got.Answer) != 1 {
		t.Fatalf("CD=1 consumed shared NSEC3 proof: %#v", got)
	}
	ecs := aggressiveNegativeRequestWithECS(aggressiveNegativeOwner, dns.TypeTXT)
	if got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, ecs); len(got.Answer) != 1 {
		t.Fatalf("raw ECS consumed shared NSEC3 proof: %#v", got)
	}
	if limiter.calls.Load() != 0 {
		t.Fatalf("CD/ECS bypass hashed %d NSEC3 names, want 0", limiter.calls.Load())
	}

	normal := aggressiveNegativeRequest(aggressiveNegativeOwner, dns.TypeSRV, true)
	assertAggressiveNegativeProof(
		t,
		aggressiveNegativeExchange(t, context.Background(), cache, downstream, normal),
		normal,
		dns.RcodeSuccess,
		dns.TypeNSEC3,
	)
	if limiter.calls.Load() != 1 {
		t.Fatalf("normal exact NODATA hashes = %d, want 1", limiter.calls.Load())
	}
	if downstreamCalls != 3 {
		t.Fatalf("downstream calls = %d, want seed + CD + ECS", downstreamCalls)
	}
}

func TestP6NSEC3ForwarderADCannotPublishSharedProof(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	const owner = "forwarded.p6.example."
	downstreamCalls := 0
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		downstreamCalls++
		if ch.Request.Msg().Question[0].Qtype == dns.TypeAAAA {
			fixture := newDenialProofNSEC3Fixture(
				t,
				time.Now().UTC(),
				owner,
				p6NSEC3Zone,
				"",
				0,
				0,
			)
			aggressiveNegativeMakeSignaturesPackable(fixture.msg)
			_ = ch.Writer.WriteMsg(fixture.msg)
			ch.Cancel()
			return
		}
		_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
		ch.Cancel()
	})

	seed := aggressiveNegativeRequest(owner, dns.TypeAAAA, true)
	_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
	if got := cache.store.DenialProofLen(); got != 0 {
		t.Fatalf("unmarked forwarder AD admitted %d NSEC3 proof entries", got)
	}

	probe := aggressiveNegativeRequest(owner, dns.TypeMX, true)
	got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, probe)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("forwarder proof escaped exact cache boundary: %#v", got)
	}
	if downstreamCalls != 2 {
		t.Fatalf("downstream calls = %d, want forwarded seed + probe", downstreamCalls)
	}
}

func TestP6NSEC3RawECSSeedCannotPublishSharedProof(t *testing.T) {
	cache := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer cache.Stop()

	const owner = "ecs-seed.p6.example."
	downstreamCalls := 0
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		downstreamCalls++
		if ch.Request.Msg().Question[0].Qtype == dns.TypeAAAA {
			fixture := newDenialProofNSEC3Fixture(
				t,
				time.Now().UTC(),
				owner,
				p6NSEC3Zone,
				"",
				0,
				0,
			)
			fixture.msg.CheckingDisabled = false
			aggressiveNegativeMakeSignaturesPackable(fixture.msg)
			aggressiveNegativeMark(
				ctx,
				fixture.msg,
				owner,
				middleware.ValidatedNegativeProofNSEC3,
			)
			_ = ch.Writer.WriteMsg(fixture.msg)
			ch.Cancel()
			return
		}
		_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request.Msg()))
		ch.Cancel()
	})

	seed := aggressiveNegativeRequest(owner, dns.TypeAAAA, true)
	seed.IsEdns0().Option = append(seed.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("203.0.113.0").To4(),
	})
	_ = aggressiveNegativeExchange(t, context.Background(), cache, downstream, seed)
	if got := cache.store.DenialProofLen(); got != 0 {
		t.Fatalf("raw ECS seed admitted %d shared NSEC3 proof entries", got)
	}

	probe := aggressiveNegativeRequest(owner, dns.TypeMX, true)
	if got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, probe); len(got.Answer) != 1 {
		t.Fatalf("unscoped probe consumed ECS-derived NSEC3 proof: %#v", got)
	}
	if downstreamCalls != 2 {
		t.Fatalf("downstream calls = %d, want ECS seed + unscoped probe", downstreamCalls)
	}
}
