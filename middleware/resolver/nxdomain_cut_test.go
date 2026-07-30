package resolver

import (
	"context"
	"crypto"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/middleware"
)

func TestNXDomainCutProvenanceRequiresLocalDNSSECValidation(t *testing.T) {
	t.Run("signed denial is marked on the exact response", func(t *testing.T) {
		fixture := newRandomQFloodFixture(t, true)
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)

		resp, err := fixture.resolve(ctx, 1)
		if err != nil {
			t.Fatalf("resolve signed NXDOMAIN: %v", err)
		}
		if resp == nil || resp.Rcode != dns.RcodeNameError || !resp.AuthenticatedData {
			t.Fatalf("signed response = %#v, want authenticated NXDOMAIN", resp)
		}

		denial, ok := middleware.ValidatedDenialForResponse(ctx, resp)
		if !ok {
			t.Fatal("locally validated NXDOMAIN has no provenance")
		}
		if denial.DeniedName != dns.CanonicalName(resp.Question[0].Name) {
			t.Fatalf("denied name = %q, want %q", denial.DeniedName, resp.Question[0].Name)
		}
		if denial.Zone != randomQBenchmarkZone {
			t.Fatalf("denial zone = %q, want %q", denial.Zone, randomQBenchmarkZone)
		}
		if denial.Proof != resp {
			t.Fatal("provenance proof must retain the exact response validated by authority()")
		}
		if _, copied := middleware.ValidatedDenialForResponse(ctx, resp.Copy()); copied {
			t.Fatal("a copied response inherited exact-response provenance")
		}
	})

	t.Run("unsigned denial is not marked", func(t *testing.T) {
		fixture := newRandomQFloodFixture(t, false)
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)

		resp, err := fixture.resolve(ctx, 2)
		if err != nil {
			t.Fatalf("resolve unsigned NXDOMAIN: %v", err)
		}
		if resp == nil || resp.Rcode != dns.RcodeNameError {
			t.Fatalf("unsigned response = %#v, want NXDOMAIN", resp)
		}
		if _, ok := middleware.ValidatedDenialForResponse(ctx, resp); ok {
			t.Fatal("unsigned NXDOMAIN received validated-denial provenance")
		}
	})

	t.Run("checking disabled bypasses provenance", func(t *testing.T) {
		fixture := newRandomQFloodFixture(t, true)
		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)

		req := new(dns.Msg)
		req.SetQuestion("m000000000000003."+randomQBenchmarkZone, dns.TypeA)
		req.SetEdns0(1232, true)
		req.CheckingDisabled = true

		resp, err := fixture.resolver.Resolve(
			ctx,
			req,
			fixture.servers,
			false,
			30,
			dns.CountLabel(randomQBenchmarkZone),
			true,
			fixture.parentDS,
		)
		if err != nil {
			t.Fatalf("resolve CD=1 NXDOMAIN: %v", err)
		}
		if resp == nil || resp.Rcode != dns.RcodeNameError || resp.AuthenticatedData {
			t.Fatalf("CD=1 response = %#v, want unauthenticated NXDOMAIN", resp)
		}
		if _, ok := middleware.ValidatedDenialForResponse(ctx, resp); ok {
			t.Fatal("CD=1 NXDOMAIN received validated-denial provenance")
		}
	})

	t.Run("wire AD bit is not a trust signal", func(t *testing.T) {
		fixture := newRandomQFloodFixture(t, false)
		var hits atomic.Uint64
		fixture.servers = startADLookingNXDomainAuthority(t, &hits)

		var meta middleware.ResponseMeta
		ctx := middleware.WithResponseMeta(context.Background(), &meta)
		resp, err := fixture.resolve(ctx, 4)
		if err != nil {
			t.Fatalf("resolve AD-looking unsigned NXDOMAIN: %v", err)
		}
		if resp == nil || resp.Rcode != dns.RcodeNameError {
			t.Fatalf("AD-looking response = %#v, want NXDOMAIN", resp)
		}
		if resp.AuthenticatedData {
			t.Fatal("resolver retained an untrusted upstream AD bit")
		}
		if _, ok := middleware.ValidatedDenialForResponse(ctx, resp); ok {
			t.Fatal("AD-looking unsigned NXDOMAIN received validated-denial provenance")
		}
		if got := hits.Load(); got != 1 {
			t.Fatalf("authoritative queries = %d, want 1", got)
		}
	})
}

func TestNXDomainCutProvenanceRejectsMismatchedEchoedQuestion(t *testing.T) {
	fixture := newRandomQFloodFixture(t, true)
	resp, err := fixture.resolve(context.Background(), 10)
	if err != nil {
		t.Fatalf("resolve signed denial fixture: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("m00000000000000b."+randomQBenchmarkZone, dns.TypeA)
	req.SetEdns0(1232, true)

	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	result, err := fixture.resolver.authority(
		ctx,
		req,
		resp,
		fixture.parentDS,
		randomQBenchmarkZone,
	)
	if !errors.Is(err, ErrQuestion) {
		t.Fatalf("mismatched echoed question = (%#v, %v), want ErrQuestion", result, err)
	}
	if _, ok := middleware.ValidatedDenialForResponse(ctx, resp); ok {
		t.Fatal("mismatched echoed question received validated-denial provenance")
	}
}

func TestNXDomainCutMinimizedAuthenticatedDenialStopsAtDeniedName(t *testing.T) {
	fixture := newRandomQFloodFixture(t, true)
	fixture.resolver.qnameMinLevel = 10

	minimizedName := "m000000000000005." + randomQBenchmarkZone
	originalName := "deep." + minimizedName
	req := new(dns.Msg)
	req.SetQuestion(originalName, dns.TypeA)
	req.SetEdns0(1232, true)

	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	resp, err := fixture.resolver.Resolve(
		ctx,
		req,
		fixture.servers,
		false,
		30,
		dns.CountLabel(randomQBenchmarkZone),
		false,
		fixture.parentDS,
	)
	if err != nil {
		t.Fatalf("resolve minimized signed NXDOMAIN: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError || !resp.AuthenticatedData {
		t.Fatalf("minimized response = %#v, want authenticated NXDOMAIN", resp)
	}
	if len(resp.Question) != 1 || !strings.EqualFold(resp.Question[0].Name, originalName) {
		t.Fatalf("response question = %+v, want original %q", resp.Question, originalName)
	}

	denial, ok := middleware.ValidatedDenialForResponse(ctx, resp)
	if !ok {
		t.Fatal("minimized authenticated NXDOMAIN has no provenance")
	}
	if denial.DeniedName != dns.CanonicalName(minimizedName) {
		t.Fatalf("denied name = %q, want minimized name %q", denial.DeniedName, minimizedName)
	}
	if denial.Proof != resp {
		t.Fatal("minimized provenance lost the exact validated response")
	}
	if got := fixture.outboundHits.Load(); got != 1 {
		t.Fatalf("authoritative queries = %d, want early RFC 8020 stop after 1", got)
	}
}

func TestNXDomainCutMinimizedNSEC3OptOutDoesNotCutDescendant(t *testing.T) {
	const (
		minimizedName = "missing." + randomQBenchmarkZone
		originalName  = "exists." + minimizedName
	)

	key, privateKey := randomQZoneKey(t, randomQBenchmarkZone)
	denial := nxDomainCutOptOutDenialRecords(
		t,
		key,
		privateKey,
		minimizedName,
		randomQBenchmarkZone,
	)
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   originalName,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("192.0.2.44").To4(),
	}
	signedAnswer := []dns.RR{
		answer,
		randomQSignRRSet(t, key, privateKey, []dns.RR{answer}),
	}

	var outboundHits atomic.Uint64
	servers := startNXDomainCutOptOutAuthority(
		t,
		minimizedName,
		originalName,
		denial,
		signedAnswer,
		&outboundHits,
	)
	cfg := &config.Config{
		DNSSEC:               "on",
		Maxdepth:             30,
		MaxConcurrentQueries: 16,
		Timeout:              config.Duration{Duration: time.Second},
	}
	r := &Resolver{
		cfg:            cfg,
		delegations:    authority.NewCache(),
		rootServers:    servers,
		dnssec:         true,
		rootKeys:       []dns.RR{key},
		netTimeout:     time.Second,
		sfGroup:        NewSingleflightWrapper(),
		circuitBreaker: newCircuitBreaker(),
		maxConcurrent:  make(chan struct{}, cfg.MaxConcurrentQueries),
		qnameMinLevel:  10,
	}

	keyResponse := new(dns.Msg)
	keyResponse.SetQuestion(randomQBenchmarkZone, dns.TypeDNSKEY)
	keyResponse.Response = true
	keyResponse.Authoritative = true
	keyResponse.Answer = append(keyResponse.Answer, key)
	keyResponse.Answer = append(
		keyResponse.Answer,
		randomQSignRRSet(t, key, privateKey, []dns.RR{key}),
	)
	dnskeyStore := &randomQWarmDNSSECStore{
		zone: randomQBenchmarkZone,
		msg:  keyResponse,
	}
	var store middleware.Store = dnskeyStore
	r.store.Store(&store)

	// Prove the minimized response is accepted and explicitly marked by the
	// real DNSSEC authority path. Without this precondition, a test that only
	// observes the later full-name lookup could also pass because validation
	// (rather than the Opt-Out cut gate) failed to produce provenance.
	minimizedReq := new(dns.Msg)
	minimizedReq.SetQuestion(minimizedName, dns.TypeA)
	minimizedReq.SetEdns0(1232, true)
	minimizedResp := new(dns.Msg)
	minimizedResp.SetRcode(minimizedReq, dns.RcodeNameError)
	minimizedResp.Authoritative = true
	minimizedResp.Ns = append(minimizedResp.Ns, denial...)
	var validationMeta middleware.ResponseMeta
	validationCtx := middleware.WithResponseMeta(context.Background(), &validationMeta)
	validated, err := r.authority(
		validationCtx,
		minimizedReq,
		minimizedResp,
		[]dns.RR{key.ToDS(dns.SHA256)},
		randomQBenchmarkZone,
	)
	if err != nil {
		t.Fatalf("validate minimized NSEC3 Opt-Out denial: %v", err)
	}
	if denialMark, ok := middleware.ValidatedDenialForResponse(validationCtx, validated); !ok ||
		denialMark.DeniedName != dns.CanonicalName(minimizedName) {
		t.Fatalf("validated Opt-Out provenance = %+v, %v", denialMark, ok)
	}

	req := new(dns.Msg)
	req.SetQuestion(originalName, dns.TypeA)
	req.SetEdns0(1232, true)
	req.RecursionDesired = false

	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	resp, err := r.Resolve(
		ctx,
		req,
		servers,
		false,
		30,
		dns.CountLabel(randomQBenchmarkZone),
		false,
		[]dns.RR{key.ToDS(dns.SHA256)},
	)
	if err != nil {
		t.Fatalf("resolve below authenticated NSEC3 Opt-Out span: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
		t.Fatalf("response = %#v, want authenticated positive answer", resp)
	}
	if len(resp.Answer) == 0 ||
		!strings.EqualFold(resp.Answer[0].Header().Name, originalName) {
		t.Fatalf("answer = %v, want record at full name %q", resp.Answer, originalName)
	}
	if got := outboundHits.Load(); got != 2 {
		t.Fatalf("authoritative queries = %d, want minimized denial plus full-name lookup", got)
	}
	if _, ok := middleware.ValidatedDenialForResponse(ctx, resp); ok {
		t.Fatal("positive descendant inherited minimized denial provenance")
	}
}

func nxDomainCutOptOutDenialRecords(
	tb testing.TB,
	key *dns.DNSKEY,
	privateKey crypto.PrivateKey,
	minimizedName string,
	zone string,
) []dns.RR {
	tb.Helper()

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	closestEncloser := nxDomainCutExactNSEC3(tb, zone, zone)
	nextCloser := nxDomainCutCoveringNSEC3(tb, minimizedName, zone, 1)
	wildcard := nxDomainCutCoveringNSEC3(tb, "*."+zone, zone, 0)

	records := []dns.RR{
		soa,
		randomQSignRRSet(tb, key, privateKey, []dns.RR{soa}),
	}
	for _, record := range []*dns.NSEC3{closestEncloser, nextCloser, wildcard} {
		records = append(
			records,
			record,
			randomQSignRRSet(tb, key, privateKey, []dns.RR{record}),
		)
	}
	return records
}

func nxDomainCutExactNSEC3(tb testing.TB, name, zone string) *dns.NSEC3 {
	tb.Helper()

	hash := dns.HashName(name, dns.SHA1, 0, "")
	record := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   hash + "." + dns.Fqdn(zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Iterations: 0,
		HashLength: 20,
		NextDomain: nxDomainCutAdjacentNSEC3Hash(tb, hash, 1),
		TypeBitMap: []uint16{
			dns.TypeNS,
			dns.TypeSOA,
			dns.TypeRRSIG,
			dns.TypeDNSKEY,
			dns.TypeNSEC3PARAM,
		},
	}
	if !record.Match(name) {
		tb.Fatalf("exact NSEC3 fixture does not match %q", name)
	}
	return record
}

func nxDomainCutCoveringNSEC3(tb testing.TB, name, zone string, flags uint8) *dns.NSEC3 {
	tb.Helper()

	hash := dns.HashName(name, dns.SHA1, 0, "")
	record := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   nxDomainCutAdjacentNSEC3Hash(tb, hash, -1) + "." + dns.Fqdn(zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 0,
		HashLength: 20,
		NextDomain: nxDomainCutAdjacentNSEC3Hash(tb, hash, 1),
		TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC3},
	}
	if !record.Cover(name) || record.Match(name) {
		tb.Fatalf("NSEC3 fixture does not strictly cover %q", name)
	}
	return record
}

func nxDomainCutAdjacentNSEC3Hash(tb testing.TB, hash string, delta int) string {
	tb.Helper()

	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	result := []byte(strings.ToUpper(hash))
	fill := byte('0')
	if delta < 0 {
		fill = 'V'
	}
	for i := len(result) - 1; i >= 0; i-- {
		index := strings.IndexByte(alphabet, result[i])
		if index < 0 {
			tb.Fatalf("invalid NSEC3 hash %q", hash)
		}
		next := index + delta
		if next < 0 || next >= len(alphabet) {
			continue
		}
		result[i] = alphabet[next]
		for j := i + 1; j < len(result); j++ {
			result[j] = fill
		}
		return string(result)
	}

	tb.Fatalf("cannot find adjacent NSEC3 value for %q", hash)
	return ""
}

func startNXDomainCutOptOutAuthority(
	tb testing.TB,
	minimizedName string,
	originalName string,
	denial []dns.RR,
	answer []dns.RR,
	hits *atomic.Uint64,
) *authority.Servers {
	tb.Helper()

	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen Opt-Out authority: %v", err)
	}
	server := &dns.Server{
		Net:        "udp",
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			hits.Add(1)
			resp := new(dns.Msg)
			switch {
			case len(req.Question) == 0:
				resp.SetRcode(req, dns.RcodeFormatError)
			case strings.EqualFold(req.Question[0].Name, minimizedName):
				resp.SetRcode(req, dns.RcodeNameError)
				resp.Ns = append(resp.Ns, denial...)
			case strings.EqualFold(req.Question[0].Name, originalName):
				resp.SetReply(req)
				resp.Answer = append(resp.Answer, answer...)
			default:
				resp.SetRcode(req, dns.RcodeServerFailure)
			}
			resp.Authoritative = true
			_ = w.WriteMsg(resp)
		}),
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	tb.Cleanup(func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	})

	return &authority.Servers{
		Zone: randomQBenchmarkZone,
		List: []*authority.Server{
			authority.NewServer(packetConn.LocalAddr().String(), authority.IPv4),
		},
	}
}

type markedTerminalDNAMEQueryer struct {
	last *dns.Msg
}

func (q *markedTerminalDNAMEQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	resp.CheckingDisabled = req.CheckingDisabled
	resp.Answer = []dns.RR{&dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    120,
		},
		Target: "missing.final.test.",
	}}
	resp.Ns = []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "target.test.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    120,
			},
			Ns:      "ns.target.test.",
			Mbox:    "hostmaster.target.test.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  120,
		},
		&dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   "a.target.test.",
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    120,
			},
			NextDomain: "z.target.test.",
			TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG},
		},
	}
	middleware.MarkValidatedDenialResponse(ctx, resp, middleware.ValidatedDenial{
		DeniedName: "missing.final.test.",
		Zone:       "target.test.",
	})
	q.last = resp
	return resp, nil
}

func TestNXDomainCutDNAMEKeepsTerminalCNAMEProofAndProvenance(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("host.alias.test.", dns.TypeA)
	req.CheckingDisabled = true

	outer := new(dns.Msg)
	outer.SetReply(req)
	outer.CheckingDisabled = true
	outer.Answer = []dns.RR{&dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   "alias.test.",
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    120,
		},
		Target: "target.test.",
	}}

	queryer := new(markedTerminalDNAMEQueryer)
	var queryerInterface middleware.Queryer = queryer
	r := new(Resolver)
	r.queryer.Store(&queryerInterface)

	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	resp, err := r.answer(ctx, req, outer, nil, "alias.test.")
	if err != nil {
		t.Fatalf("merge DNAME target NXDOMAIN: %v", err)
	}
	if resp != outer || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("DNAME result = %#v, want outer response rewritten to NXDOMAIN", resp)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("DNAME result answers = %d, want outer DNAME plus target CNAME", len(resp.Answer))
	}
	if len(resp.Ns) != len(queryer.last.Ns) {
		t.Fatalf("DNAME result authority records = %d, want target proof count %d", len(resp.Ns), len(queryer.last.Ns))
	}

	denial, ok := middleware.ValidatedDenialForResponse(ctx, resp)
	if !ok {
		t.Fatal("DNAME merge lost target denial provenance")
	}
	if denial.DeniedName != "missing.final.test." || denial.Zone != "target.test." {
		t.Fatalf("DNAME denial provenance = %+v", denial)
	}
	if denial.Proof != queryer.last {
		t.Fatal("DNAME merge attributed proof to the rewritten outer response")
	}
}

func startADLookingNXDomainAuthority(tb testing.TB, hits *atomic.Uint64) *authority.Servers {
	tb.Helper()

	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen AD-looking authority: %v", err)
	}
	server := &dns.Server{
		Net:        "udp",
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			hits.Add(1)
			resp := new(dns.Msg)
			resp.SetRcode(req, dns.RcodeNameError)
			resp.Authoritative = true
			resp.AuthenticatedData = true
			resp.Ns = []dns.RR{&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   randomQBenchmarkZone,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Ns:      "ns1." + randomQBenchmarkZone,
				Mbox:    "hostmaster." + randomQBenchmarkZone,
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  300,
			}}
			_ = w.WriteMsg(resp)
		}),
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	tb.Cleanup(func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	})

	return &authority.Servers{
		Zone: randomQBenchmarkZone,
		List: []*authority.Server{
			authority.NewServer(packetConn.LocalAddr().String(), authority.IPv4),
		},
	}
}
