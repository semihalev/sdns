package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
	internalcache "github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/middleware"
)

// attackWireRecorder is a hermetic authoritative server with a wire-level
// query counter. Adversarial recursion tests use it to take a numerical snapshot
// of current outbound work without depending on the public DNS.
type attackWireRecorder struct {
	total atomic.Int64

	mu       sync.Mutex
	byQuery  map[dns.Question]int
	server   *dns.Server
	packet   net.PacketConn
	shutdown sync.Once
}

func startAttackWireRecorder(t testing.TB, answer func(dns.Question) *dns.Msg) *attackWireRecorder {
	t.Helper()

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen attack fixture: %v", err)
	}

	recorder := &attackWireRecorder{
		byQuery: make(map[dns.Question]int),
		packet:  packet,
	}
	recorder.server = &dns.Server{
		Net:        "udp",
		PacketConn: packet,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			if len(req.Question) == 0 {
				return
			}

			q := req.Question[0]
			recorder.total.Add(1)
			recorder.mu.Lock()
			recorder.byQuery[q]++
			recorder.mu.Unlock()

			src := answer(q)
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Compress = true
			if src != nil {
				reply.Authoritative = src.Authoritative
				reply.Rcode = src.Rcode
				reply.Answer = src.Answer
				reply.Ns = src.Ns
				reply.Extra = src.Extra
			}
			_ = w.WriteMsg(reply)
		}),
	}

	go func() {
		_ = recorder.server.ActivateAndServe()
	}()
	t.Cleanup(recorder.stop)

	return recorder
}

func (r *attackWireRecorder) addr() string {
	return r.packet.LocalAddr().String()
}

func (r *attackWireRecorder) count() int64 {
	return r.total.Load()
}

func (r *attackWireRecorder) countQuestion(q dns.Question) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byQuery[q]
}

func (r *attackWireRecorder) stop() {
	r.shutdown.Do(func() {
		_ = r.server.Shutdown()
		_ = r.packet.Close()
	})
}

// attackAddressOracle models the policy-aware Queryer leg used to resolve
// glue-less NS targets. Each call is one client-shaped A sub-query; in
// production it can fan out into more than one authoritative wire exchange.
// Keeping this seam explicit gives request-wide resource accounting a stable
// before/after counter.
type attackAddressOracle struct {
	total atomic.Int64

	mu        sync.Mutex
	answers   map[string]net.IP
	questions []dns.Question
	record    bool
}

func (o *attackAddressOracle) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Question) == 0 {
		return nil, errors.New("attack address oracle: empty question")
	}

	q := req.Question[0]
	o.total.Add(1)
	ip := o.answers[strings.ToLower(q.Name)]
	if o.record {
		o.mu.Lock()
		o.questions = append(o.questions, q)
		o.mu.Unlock()
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	if q.Qtype != dns.TypeA || ip == nil {
		resp.Rcode = dns.RcodeNameError
		return resp, nil
	}
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: ip,
	}}
	return resp, nil
}

func (o *attackAddressOracle) count() int64 {
	return o.total.Load()
}

func (o *attackAddressOracle) snapshotQuestions() []dns.Question {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]dns.Question(nil), o.questions...)
}

// attackDNAMEQueryer emulates the resolver leg behind Queryer.Query for two
// zones that DNAME into one another. It calls answer recursively so every
// follow-up traverses checkDname/internalExchange exactly as a real sub-
// pipeline would, while avoiding network and cache effects in the counter.
type attackDNAMEQueryer struct {
	resolver *Resolver
	total    atomic.Int64

	mu    sync.Mutex
	names []string
}

func (q *attackDNAMEQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Question) == 0 {
		return nil, errors.New("attack DNAME queryer: empty question")
	}

	name := strings.ToLower(req.Question[0].Name)
	q.total.Add(1)
	q.mu.Lock()
	q.names = append(q.names, name)
	q.mu.Unlock()

	var owner, target string
	switch {
	case dns.IsSubDomain("a.loop.test.", name):
		owner, target = "a.loop.test.", "b.loop.test."
	case dns.IsSubDomain("b.loop.test.", name):
		owner, target = "b.loop.test.", "a.loop.test."
	default:
		return nil, fmt.Errorf("attack DNAME queryer: unexpected name %q", name)
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Answer = []dns.RR{&dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Target: target,
	}}

	// CD=1 isolates alias-chain work from DNSSEC validation so this fixture
	// measures only the DNAME recursion dimension.
	resp.CheckingDisabled = true
	return q.resolver.answer(ctx, req, resp, nil, owner)
}

func (q *attackDNAMEQueryer) count() int64 {
	return q.total.Load()
}

func (q *attackDNAMEQueryer) snapshotNames() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.names...)
}

// newAttackHarnessResolver constructs only the resolver state needed by the
// hermetic attack fixtures. Unlike NewResolver it deliberately starts no root
// priming goroutine, so every counted request belongs to the test operation.
func newAttackHarnessResolver(root *authority.Servers) *Resolver {
	const maxConcurrent = 128

	cfg := &config.Config{
		DNSSEC:               "off",
		Maxdepth:             30,
		MaxConcurrentQueries: maxConcurrent,
		Timeout:              config.Duration{Duration: time.Second},
	}
	return &Resolver{
		cfg:            cfg,
		delegations:    authority.NewCache(),
		rootServers:    root,
		glueV4:         internalcache.New(defaultCacheSize),
		dnssec:         false,
		qnameMinLevel:  0,
		netTimeout:     time.Second,
		sfGroup:        NewSingleflightWrapper(),
		circuitBreaker: newCircuitBreaker(),
		maxConcurrent:  make(chan struct{}, maxConcurrent),
	}
}

func installAttackQueryer(r *Resolver, queryer middleware.Queryer) {
	r.queryer.Store(&queryer)
}

// TestRecursionAttackHarness_NXNSReferralFanout records the work
// caused by one glue-less referral carrying many out-of-bailiwick NS targets:
//
//	1 root-side referral query
//	N policy-aware A sub-queries for the advertised NS names
//	1 child-authority query (all names resolve to the same address)
//
// The exact NS-address count is logged rather than required: current behaviour
// dispatches all N lookups, while a request-wide cap may legitimately stop
// earlier. The fan-out benchmark below retains the numerical baseline.
func TestRecursionAttackHarness_NXNSReferralFanout(t *testing.T) {
	// Keep the referral below the resolver's UDP-to-TCP fallback threshold;
	// the address-fanout benchmark below covers larger 32/64-name sets
	// without coupling that measurement to message transport size.
	const nsCount = 16

	referral := make([]dns.RR, 0, nsCount)
	addresses := make(map[string]net.IP, nsCount)
	childIP := net.IPv4(192, 0, 2, 1)
	for i := 0; i < nsCount; i++ {
		host := fmt.Sprintf("n%02d.evil.", i)
		referral = append(referral, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   "victim.test.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Ns: host,
		})
		addresses[host] = childIP
	}

	root := startAttackWireRecorder(t, func(dns.Question) *dns.Msg {
		return &dns.Msg{Ns: referral}
	})
	child := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		msg := &dns.Msg{
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 200),
			}},
		}
		msg.Authoritative = true
		return msg
	})

	mapper := func(addr string) string {
		if addr == net.JoinHostPort(childIP.String(), "53") {
			return child.addr()
		}
		return addr
	}

	rootServers := &authority.Servers{
		Zone: ".",
		List: []*authority.Server{
			authority.NewServer(root.addr(), authority.IPv4),
		},
		CheckingDisable: true,
	}
	r := newAttackHarnessResolver(rootServers)
	r.resolveTarget.Store(&mapper)

	oracle := &attackAddressOracle{answers: addresses, record: true}
	installAttackQueryer(r, oracle)

	req := new(dns.Msg)
	req.SetQuestion("www.victim.test.", dns.TypeA)
	req.CheckingDisabled = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, contextKeyRequestID, req.Id)

	resp, err := r.Resolve(ctx, req, rootServers, false, 30, 0, true, nil)
	if err != nil {
		t.Fatalf("NXNS fixture resolution failed: %v (root_wire=%d ns_address_subqueries=%d child_wire=%d)",
			err, root.count(), oracle.count(), child.count())
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("NXNS fixture returned no terminal answer: resp=%v", resp)
	}

	if got := root.count(); got != 1 {
		t.Fatalf("root referral wire queries = %d, want 1", got)
	}
	nsAddressQueries := oracle.count()
	if nsAddressQueries < 1 || nsAddressQueries > int64(nsCount) {
		t.Fatalf("glue-less NS address sub-queries = %d, want within [1,%d]", nsAddressQueries, nsCount)
	}
	questions := oracle.snapshotQuestions()
	if int64(len(questions)) != nsAddressQueries {
		t.Fatalf("recorded NS address questions = %d, counter = %d", len(questions), nsAddressQueries)
	}
	seenNames := make(map[string]struct{}, len(questions))
	for _, q := range questions {
		if q.Qtype != dns.TypeA {
			t.Fatalf("NS address question type = %s, want A", dns.TypeToString[q.Qtype])
		}
		if q.Qclass != dns.ClassINET {
			t.Fatalf("NS address question class = %s, want IN", dns.ClassToString[q.Qclass])
		}
		name := strings.ToLower(q.Name)
		if _, ok := addresses[name]; !ok {
			t.Fatalf("unexpected NS address question: %s", q.String())
		}
		if _, duplicate := seenNames[name]; duplicate {
			t.Fatalf("duplicate NS address question: %s", q.String())
		}
		seenNames[name] = struct{}{}
	}
	if got := child.count(); got != 1 {
		t.Fatalf("child authority wire queries = %d, want 1 for the deduplicated address", got)
	}

	logicalOutbound := root.count() + oracle.count() + child.count()
	t.Logf("NXNS baseline: ns=%d root_wire=%d ns_address_subqueries=%d child_wire=%d logical_outbound=%d",
		nsCount, root.count(), oracle.count(), child.count(), logicalOutbound)
}

// TestRecursionAttackHarness_DelegationLoopWireBound drives a malicious
// authority that refers the resolver back to the very same zone. It upgrades
// the existing progressingReferral unit coverage into a wire-counted fixture:
// the first response is rejected, no NS-address lookup is started, and the
// attacker receives exactly one query.
func TestRecursionAttackHarness_DelegationLoopWireBound(t *testing.T) {
	selfReferral := []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{
			Name:   "loop.test.",
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns: "ns.loop.test.",
	}}
	attacker := startAttackWireRecorder(t, func(dns.Question) *dns.Msg {
		return &dns.Msg{Ns: selfReferral}
	})

	servers := &authority.Servers{
		Zone: "loop.test.",
		List: []*authority.Server{
			authority.NewServer(attacker.addr(), authority.IPv4),
		},
		CheckingDisable: true,
	}
	r := newAttackHarnessResolver(servers)

	req := new(dns.Msg)
	req.SetQuestion("www.loop.test.", dns.TypeA)
	req.CheckingDisabled = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := r.Resolve(ctx, req, servers, false, 30, dns.CountLabel(servers.Zone), true, nil)
	if !errors.Is(err, errParentDetection) {
		t.Fatalf("self-referral error = %v, want errParentDetection", err)
	}
	if got := attacker.count(); got != 1 {
		t.Fatalf("self-referral wire queries = %d, want 1", got)
	}
	if got := attacker.countQuestion(req.Question[0]); got != 1 {
		t.Fatalf("original-question wire queries = %d, want 1", got)
	}

	t.Logf("delegation-loop baseline: wire_queries=%d terminal_error=%v", attacker.count(), err)
}

// TestRecursionAttackHarness_DNAMEPingPongCount measures a two-zone DNAME
// cycle. The resolver must terminate at maxDnameDepth, and the counter pins the
// exact number of internal follow-ups before the resolver's existing depth cap.
func TestRecursionAttackHarness_DNAMEPingPongCount(t *testing.T) {
	r := &Resolver{dnssec: false}
	loop := &attackDNAMEQueryer{resolver: r}
	installAttackQueryer(r, loop)

	req := new(dns.Msg)
	req.SetQuestion("host.a.loop.test.", dns.TypeA)
	req.CheckingDisabled = true
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.CheckingDisabled = true
	resp.Answer = []dns.RR{&dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   "a.loop.test.",
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Target: "b.loop.test.",
	}}

	got, err := r.answer(context.Background(), req, resp, nil, "a.loop.test.")
	if !errors.Is(err, errMaxDepth) {
		t.Fatalf("DNAME loop error = %v, want errMaxDepth", err)
	}
	if got != nil {
		t.Fatalf("DNAME loop returned a partial response; want nil on depth exhaustion: %v", got)
	}
	if count := loop.count(); count != maxDnameDepth {
		t.Fatalf("DNAME internal follow-ups = %d, want maxDnameDepth=%d", count, maxDnameDepth)
	}

	names := loop.snapshotNames()
	for i, name := range names {
		wantSuffix := "b.loop.test."
		if i%2 == 1 {
			wantSuffix = "a.loop.test."
		}
		if !dns.IsSubDomain(wantSuffix, name) {
			t.Fatalf("DNAME follow-up %d = %q, want descendant of %q", i, name, wantSuffix)
		}
	}

	t.Logf("DNAME-loop baseline: internal_followups=%d terminal_error=%v", loop.count(), err)
}

// BenchmarkRecursionAttackHarness_NXNSAddressFanout quantifies the current
// linear NS-address lookup cost independently of network latency. The custom
// metric records how many advertised glue-less NS names produce a sub-query.
func BenchmarkRecursionAttackHarness_NXNSAddressFanout(b *testing.B) {
	for _, nsCount := range []int{1, 8, 32, 64} {
		b.Run(fmt.Sprintf("NS_%d", nsCount), func(b *testing.B) {
			hosts := make(hostSet, nsCount)
			addresses := make(map[string]net.IP, nsCount)
			for i := 0; i < nsCount; i++ {
				host := fmt.Sprintf("n%02d.bench.evil.", i)
				hosts[host] = struct{}{}
				addresses[host] = net.IPv4(192, 0, 2, byte(i+1))
			}

			var totalSubqueries int64
			r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
			oracle := &attackAddressOracle{answers: addresses}
			installAttackQueryer(r, oracle)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				for host := range hosts {
					r.removeIPv4Cache(host)
				}
				authservers := &authority.Servers{
					Zone:            "victim.test.",
					CheckingDisable: true,
				}
				q := dns.Question{Name: "victim.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
				before := oracle.count()
				b.StartTimer()
				_ = r.lookupV4Nss(
					context.Background(),
					q,
					authservers,
					internalcache.Key(q, true),
					nil,
					make(hostSet),
					hosts,
					true,
					time.Now().Add(time.Minute),
				)
				b.StopTimer()
				totalSubqueries += oracle.count() - before
			}
			b.ReportMetric(float64(totalSubqueries)/float64(b.N), "ns-address-subqueries/op")
		})
	}
}
