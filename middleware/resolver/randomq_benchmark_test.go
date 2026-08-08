package resolver

import (
	"context"
	"crypto"
	"fmt"
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

const randomQBenchmarkZone = "randomq.test."

// randomQWarmDNSSECStore models the steady-state resolver cache: the zone's
// DNSKEY RRset has already been fetched, but every random QNAME is new. Keeping
// the DNSKEY lookup in memory makes the benchmark measure the per-denial cost
// and authoritative UDP fan-out rather than cold chain construction.
type randomQWarmDNSSECStore struct {
	zone string
	msg  *dns.Msg
	hits atomic.Uint64
}

func (s *randomQWarmDNSSECStore) Get(req *dns.Msg) (*dns.Msg, bool) {
	if len(req.Question) == 0 {
		return nil, false
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeDNSKEY || !strings.EqualFold(q.Name, s.zone) {
		return nil, false
	}
	s.hits.Add(1)
	return s.msg.Copy(), true
}

func (s *randomQWarmDNSSECStore) SetFromResponse(*dns.Msg, bool, time.Time) {}

type randomQFloodFixture struct {
	resolver     *Resolver
	servers      *authority.Servers
	parentDS     []dns.RR
	dnskeyStore  *randomQWarmDNSSECStore
	outboundHits atomic.Uint64
}

func newRandomQFloodFixture(tb testing.TB, signed bool) *randomQFloodFixture {
	tb.Helper()

	key, privateKey := randomQZoneKey(tb, randomQBenchmarkZone)
	denial := randomQDenialRecords(tb, key, privateKey, signed)

	fixture := &randomQFloodFixture{}
	addr := startRandomQAuthority(tb, denial, &fixture.outboundHits)
	fixture.servers = &authority.Servers{
		Zone: randomQBenchmarkZone,
		List: []*authority.Server{
			authority.NewServer(addr, authority.IPv4),
		},
	}

	cfg := &config.Config{
		DNSSEC:               "on",
		Maxdepth:             30,
		MaxConcurrentQueries: 16,
		Timeout:              config.Duration{Duration: time.Second},
	}
	fixture.resolver = &Resolver{
		cfg:             cfg,
		delegations:     authority.NewCache(),
		rootServers:     fixture.servers,
		dnssec:          true,
		rootKeys:        []dns.RR{key},
		netTimeout:      time.Second,
		sfGroup:         NewSingleflightWrapper(),
		circuitBreaker:  newCircuitBreaker(),
		maxConcurrent:   make(chan struct{}, cfg.MaxConcurrentQueries),
		resolutionSlots: make(chan struct{}, cfg.MaxConcurrentQueries),
	}

	if signed {
		keyRRset := []dns.RR{key}
		keyResponse := new(dns.Msg)
		keyResponse.SetQuestion(randomQBenchmarkZone, dns.TypeDNSKEY)
		keyResponse.Response = true
		keyResponse.Authoritative = true
		keyResponse.Answer = append(keyResponse.Answer, key)
		keyResponse.Answer = append(keyResponse.Answer, randomQSignRRSet(tb, key, privateKey, keyRRset))

		fixture.parentDS = []dns.RR{key.ToDS(dns.SHA256)}
		fixture.dnskeyStore = &randomQWarmDNSSECStore{
			zone: randomQBenchmarkZone,
			msg:  keyResponse,
		}
		var store middleware.Store = fixture.dnskeyStore
		fixture.resolver.store.Store(&store)
	}

	return fixture
}

func (f *randomQFloodFixture) resolve(ctx context.Context, sequence uint64) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(fmt.Sprintf("m%015x.%s", sequence, randomQBenchmarkZone), dns.TypeA)
	req.SetEdns0(1232, true)
	req.RecursionDesired = false
	req.CheckingDisabled = false

	// Start directly at the already-known authoritative cut. This isolates the
	// random-label workload from root/TLD discovery while retaining the real
	// resolver lookup, wire exchange, DNSSEC validation, and denial-proof path.
	return f.resolver.Resolve(
		ctx,
		req,
		f.servers,
		false,
		30,
		dns.CountLabel(randomQBenchmarkZone),
		true,
		f.parentDS,
	)
}

func randomQZoneKey(tb testing.TB, zone string) (*dns.DNSKEY, crypto.PrivateKey) {
	tb.Helper()

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	privateKey, err := key.Generate(256)
	if err != nil {
		tb.Fatalf("generate %s DNSKEY: %v", zone, err)
	}
	return key, privateKey
}

func randomQSignRRSet(tb testing.TB, key *dns.DNSKEY, privateKey crypto.PrivateKey, rrset []dns.RR) *dns.RRSIG {
	tb.Helper()

	hdr := rrset[0].Header()
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: hdr.Name, Rrtype: dns.TypeRRSIG, Class: hdr.Class, Ttl: hdr.Ttl},
		TypeCovered: hdr.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(hdr.Name)), //nolint:gosec // fixture names have only a few labels
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(now.Add(6 * time.Hour).Unix()),  //nolint:gosec // RFC 4034 serial timestamp
		Inception:   uint32(now.Add(-6 * time.Hour).Unix()), //nolint:gosec // RFC 4034 serial timestamp
		KeyTag:      key.KeyTag(),
		SignerName:  key.Header().Name,
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		tb.Fatalf("generated private key %T does not implement crypto.Signer", privateKey)
	}
	if err := sig.Sign(signer, rrset); err != nil {
		tb.Fatalf("sign %s %s: %v", hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}
	return sig
}

func randomQDenialRecords(tb testing.TB, key *dns.DNSKEY, privateKey crypto.PrivateKey, signed bool) []dns.RR {
	tb.Helper()

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: randomQBenchmarkZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + randomQBenchmarkZone,
		Mbox:    "hostmaster." + randomQBenchmarkZone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	// Every generated label begins with "m", so a. -> z. proves QNAME
	// non-existence. The apex -> a. interval independently covers
	// *.randomq.test., completing the RFC 4035 NXDOMAIN proof.
	apexNSEC := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: randomQBenchmarkZone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "a." + randomQBenchmarkZone,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	coveringNSEC := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a." + randomQBenchmarkZone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z." + randomQBenchmarkZone,
		TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC},
	}

	records := []dns.RR{soa}
	if !signed {
		return records
	}
	records = append(records,
		randomQSignRRSet(tb, key, privateKey, []dns.RR{soa}),
		apexNSEC,
		randomQSignRRSet(tb, key, privateKey, []dns.RR{apexNSEC}),
		coveringNSEC,
		randomQSignRRSet(tb, key, privateKey, []dns.RR{coveringNSEC}),
	)
	return records
}

func startRandomQAuthority(tb testing.TB, denial []dns.RR, hits *atomic.Uint64) string {
	tb.Helper()

	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen random-QNAME authority: %v", err)
	}
	server := &dns.Server{
		Net:        "udp",
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			hits.Add(1)
			resp := new(dns.Msg)
			resp.SetRcode(req, dns.RcodeNameError)
			resp.Authoritative = true
			resp.Ns = append(resp.Ns, denial...)
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
	return packetConn.LocalAddr().String()
}

// TestResolverRandomQFloodHarness proves that both resolver-only fixtures
// reach the authoritative server and that the signed variant exercises real
// DNSSEC validation (AD=1) rather than merely carrying RRSIG-shaped records.
func TestResolverRandomQFloodHarness(t *testing.T) {
	const queries = 16

	for _, tc := range []struct {
		name   string
		signed bool
	}{
		{name: "unsigned", signed: false},
		{name: "signed_warm_dnskey", signed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRandomQFloodFixture(t, tc.signed)
			for i := uint64(0); i < queries; i++ {
				resp, err := fixture.resolve(context.Background(), i)
				if err != nil {
					t.Fatalf("resolve random QNAME %d: %v", i, err)
				}
				if resp.Rcode != dns.RcodeNameError {
					t.Fatalf("resolve random QNAME %d: rcode=%s, want NXDOMAIN", i, dns.RcodeToString[resp.Rcode])
				}
				if resp.AuthenticatedData != tc.signed {
					t.Fatalf("resolve random QNAME %d: AD=%v, want %v", i, resp.AuthenticatedData, tc.signed)
				}
			}

			if got := fixture.outboundHits.Load(); got != queries {
				t.Fatalf("outbound authoritative queries=%d, want %d", got, queries)
			}
			if tc.signed {
				if got := fixture.dnskeyStore.hits.Load(); got != queries {
					t.Fatalf("warm DNSKEY cache lookups=%d, want %d", got, queries)
				}
			}
		})
	}
}

// BenchmarkResolverRandomQNXDOMAINFlood is a resolver-only baseline for
// water-torture style traffic. Each operation uses a deterministic,
// never-repeated label and reports the actual number of authoritative UDP
// requests. It calls Resolver.Resolve directly, so middleware cache and
// negative-proof reuse are outside this benchmark's scope.
func BenchmarkResolverRandomQNXDOMAINFlood(b *testing.B) {
	for _, tc := range []struct {
		name   string
		signed bool
	}{
		{name: "unsigned", signed: false},
		{name: "signed_warm_dnskey", signed: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			fixture := newRandomQFloodFixture(b, tc.signed)
			ctx := context.Background()
			outboundBefore := fixture.outboundHits.Load()
			var dnskeyBefore uint64
			if fixture.dnskeyStore != nil {
				dnskeyBefore = fixture.dnskeyStore.hits.Load()
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := fixture.resolve(ctx, uint64(i))
				if err != nil {
					b.Fatalf("resolve random QNAME %d: %v", i, err)
				}
				if resp.Rcode != dns.RcodeNameError || resp.AuthenticatedData != tc.signed {
					b.Fatalf("resolve random QNAME %d: rcode=%s AD=%v", i, dns.RcodeToString[resp.Rcode], resp.AuthenticatedData)
				}
			}
			b.StopTimer()

			outbound := fixture.outboundHits.Load() - outboundBefore
			b.ReportMetric(float64(outbound)/float64(b.N), "outbound/op")
			if fixture.dnskeyStore != nil {
				dnskeyHits := fixture.dnskeyStore.hits.Load() - dnskeyBefore
				b.ReportMetric(float64(dnskeyHits)/float64(b.N), "dnskey-cache-lookups/op")
			}
		})
	}
}
