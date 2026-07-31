package resolver

import (
	"context"
	"errors"
	"net"
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

func TestResolverResolutionAttemptGuardClosesEDNSRetryEscape(t *testing.T) {
	var calls atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if calls.Add(1) == 1 {
			resp.Rcode = dns.RcodeFormatError
		} else {
			resp.Question = []dns.Question{{
				Name:   "mismatch.example.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}}
		}
		_ = w.WriteMsg(resp)
	})
	addr, stop := startTestDNSServer(t, handler)
	defer stop()

	ledger := enforceWorkLedger(100, 100)
	r := &Resolver{cfg: &config.Config{}, netTimeout: time.Second}
	req := new(dns.Msg)
	req.SetQuestion("retry-escape.example.", dns.TypeA)
	req.SetEdns0(1232, true)
	server := authority.NewServer(addr, authority.IPv4)
	rs := &resolveState{req: req, requestID: req.Id, work: ledger}
	ctx, _ := middleware.EnsureResolutionAttemptGuard(context.Background())
	ctx = middleware.WithRecursionWork(ctx, ledger)

	_, err := r.exchange(ctx, rs, "tcp", req, server, 0)
	if !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("exchange error = %v, want ErrResolutionAttemptLimit", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("TCP wire attempts = %d, want RFC 9520 cap 3", got)
	}
	if got := ledger.Snapshot().OutboundQueries; got != 3 {
		t.Fatalf("recursion work debits = %d, want 3 (guard before debit)", got)
	}
}

func TestResolutionAttemptLimitDoesNotPoisonCircuitBreaker(t *testing.T) {
	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	server := authority.NewServer("192.0.2.50:53", authority.IPv4)
	servers := &authority.Servers{Zone: ".", List: []*authority.Server{server}}
	req := new(dns.Msg)
	req.SetQuestion("guard-circuit.example.", dns.TypeA)
	ctx, guard := middleware.EnsureResolutionAttemptGuard(context.Background())
	for range 3 {
		if err := guard.Begin(req.Question[0], server.Addr, "udp"); err != nil {
			t.Fatal(err)
		}
	}

	_, err := r.lookup(ctx, &resolveState{req: req, requestID: req.Id}, req, servers)
	if !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("lookup error = %v, want ErrResolutionAttemptLimit", err)
	}
	r.circuitBreaker.mu.RLock()
	_, recorded := r.circuitBreaker.failures[server.Addr]
	r.circuitBreaker.mu.RUnlock()
	if recorded {
		t.Fatal("request-local attempt exhaustion was recorded as an upstream failure")
	}
}

func TestResolverHandlerMarksAttemptLimitResponse(t *testing.T) {
	server := authority.NewServer("192.0.2.53:53", authority.IPv4)
	root := &authority.Servers{Zone: ".", List: []*authority.Server{server}}
	r := newAttackHarnessResolver(root)
	r.cfg.QueryTimeout.Duration = time.Second
	h := &DNSHandler{resolver: r, cfg: r.cfg}

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(1232, true)
	req.RecursionDesired = true
	ctx, guard := middleware.EnsureResolutionAttemptGuard(context.Background())
	for range 3 {
		if err := guard.Begin(req.Question[0], server.Addr, "udp"); err != nil {
			t.Fatal(err)
		}
	}

	resp := h.handle(ctx, req)
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("handler response = %#v, want SERVFAIL", resp)
	}
	if err := middleware.RequestLocalFailureForResponse(ctx, resp); !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("handler response provenance = %v, want ErrResolutionAttemptLimit", err)
	}
	if err := middleware.RequestLocalFailureForResponse(ctx, resp.Copy()); err != nil {
		t.Fatalf("copied handler response inherited exact provenance: %v", err)
	}
}

func TestResolverHandlerMarksDerivedDeadlineResponse(t *testing.T) {
	server := authority.NewServer("192.0.2.53:53", authority.IPv4)
	root := &authority.Servers{Zone: ".", List: []*authority.Server{server}}
	r := newAttackHarnessResolver(root)
	r.cfg.QueryTimeout.Duration = -time.Second
	h := &DNSHandler{resolver: r, cfg: r.cfg}

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(1232, true)
	req.RecursionDesired = true
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)

	resp := h.handle(ctx, req)
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("handler response = %#v, want SERVFAIL", resp)
	}
	if err := middleware.RequestLocalFailureForResponse(ctx, resp); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handler response provenance = %v, want context deadline", err)
	}
}

type resolverErrorQueryer struct {
	err   error
	calls atomic.Int32
}

func (q *resolverErrorQueryer) Query(context.Context, *dns.Msg) (*dns.Msg, error) {
	q.calls.Add(1)
	return nil, q.err
}

func TestResolverHandlerMarksQueryerRecursionLimitResponse(t *testing.T) {
	wire := startAttackWireRecorder(t, func(dns.Question) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{&dns.DNAME{
				Hdr: dns.RR_Header{
					Name:   "a.loop.test.",
					Rrtype: dns.TypeDNAME,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Target: "b.loop.test.",
			}},
		}
	})
	server := authority.NewServer(wire.addr(), authority.IPv4)
	root := &authority.Servers{Zone: ".", List: []*authority.Server{server}}
	r := newAttackHarnessResolver(root)
	r.cfg.QueryTimeout.Duration = time.Second
	queryer := &resolverErrorQueryer{err: middleware.ErrMaxRecursion}
	installAttackQueryer(r, queryer)
	h := &DNSHandler{resolver: r, cfg: r.cfg}

	req := new(dns.Msg)
	req.SetQuestion("host.a.loop.test.", dns.TypeA)
	req.SetEdns0(1232, true)
	req.RecursionDesired = true
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)

	resp := h.handle(ctx, req)
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("handler response = %#v, want SERVFAIL", resp)
	}
	if got := queryer.calls.Load(); got != 1 {
		t.Fatalf("DNAME target queryer calls = %d, want 1", got)
	}
	if err := middleware.RequestLocalFailureForResponse(ctx, resp); !errors.Is(err, middleware.ErrMaxRecursion) {
		t.Fatalf("handler response provenance = %v, want ErrMaxRecursion", err)
	}
}

func TestPickFallbackResponsePreservesRequestLocalAttemptError(t *testing.T) {
	servfail := new(dns.Msg)
	servfail.Rcode = dns.RcodeServerFailure
	resp, err := pickFallbackResponse(
		[]*dns.Msg{servfail},
		nil,
		[]error{middleware.ErrResolutionAttemptLimit},
	)
	if resp != nil || !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("SERVFAIL fallback = resp:%#v err:%v, want regroupable attempt-limit error", resp, err)
	}

	nxdomain := new(dns.Msg)
	nxdomain.Rcode = dns.RcodeNameError
	resp, err = pickFallbackResponse(
		[]*dns.Msg{nxdomain},
		nil,
		[]error{middleware.ErrResolutionAttemptLimit},
	)
	if err != nil || resp != nxdomain {
		t.Fatalf("NXDOMAIN fallback = resp:%#v err:%v, want useful authority response", resp, err)
	}
}

func TestLookupDeduplicatesAuthorityEndpoints(t *testing.T) {
	wire := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 60),
			}},
		}
	})
	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	server := authority.NewServer(wire.addr(), authority.IPv4)
	servers := &authority.Servers{
		Zone: ".",
		List: []*authority.Server{server, server, server, server},
	}
	req := new(dns.Msg)
	req.SetQuestion("dedupe.example.", dns.TypeA)
	ctx, _ := middleware.EnsureResolutionAttemptGuard(context.Background())

	resp, err := r.lookup(ctx, &resolveState{req: req, requestID: req.Id}, req, servers)
	if err != nil || resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("lookup = resp:%#v err:%v, want successful answer", resp, err)
	}
	if got := wire.count(); got != 1 {
		t.Fatalf("duplicate authority wire attempts = %d, want 1", got)
	}
}

func TestCheckGlueRRDeduplicatesEndpointsWithoutDroppingHostCache(t *testing.T) {
	r := &Resolver{
		cfg:    &config.Config{},
		glueV4: internalcache.New(defaultCacheSize),
	}
	req := new(dns.Msg)
	req.SetQuestion("www.child.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns1.child.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 70),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns1.child.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 70),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns2.child.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 70),
		},
	}
	hosts := hostSet{
		"ns1.child.example.": {},
		"ns2.child.example.": {},
	}

	servers, foundV4, _ := r.checkGlueRR(resp, hosts, 2)
	if got := len(servers.List); got != 1 {
		t.Fatalf("deduplicated glue endpoints = %d, want 1", got)
	}
	if len(foundV4) != 2 {
		t.Fatalf("found glue hosts = %v, want both NS owners", foundV4)
	}
	for name := range hosts {
		addrs, ok := r.getIPv4Cache(name)
		if !ok || len(addrs) != 1 || addrs[0] != "192.0.2.70" {
			t.Fatalf("cached glue for %s = %v, %v; want one address", name, addrs, ok)
		}
	}
}

func TestParseRootServersDeduplicatesCanonicalEndpoints(t *testing.T) {
	cfg := &config.Config{
		IPv6Access: true,
		RootServers: []string{
			"192.0.2.80:53",
			"192.0.2.80:053",
		},
		Root6Servers: []string{
			"[2001:db8::80]:53",
			"[2001:0DB8:0:0::80]:053",
		},
	}
	r := new(Resolver)
	r.parseRootServers(cfg)
	if got := len(r.rootServers.List); got != 2 {
		t.Fatalf("canonical root endpoints = %d, want one IPv4 and one IPv6", got)
	}
}

type attemptGuardSignalContext struct {
	context.Context
	once  sync.Once
	ready chan struct{}
}

type resolutionFailureRecorder struct {
	mu      sync.Mutex
	records []string
	clears  []string
}

type selectiveNSAddressQueryer struct {
	failAll bool
	calls   atomic.Int32
}

func (q *selectiveNSAddressQueryer) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	q.calls.Add(1)
	if q.failAll || req.Question[0].Name == "limited.child.example." {
		return nil, middleware.ErrResolutionAttemptLimit
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(192, 0, 2, 91),
	}}
	return resp, nil
}

func (s *resolutionFailureRecorder) Get(*dns.Msg) (*dns.Msg, bool) { return nil, false }

func (s *resolutionFailureRecorder) SetFromResponse(*dns.Msg, bool, time.Time) {}

func (s *resolutionFailureRecorder) RecordZoneFailure(_ dns.Question, zone string) {
	s.mu.Lock()
	s.records = append(s.records, zone)
	s.mu.Unlock()
}

func (s *resolutionFailureRecorder) ClearZoneFailure(_ dns.Question, zone string) {
	s.mu.Lock()
	s.clears = append(s.clears, zone)
	s.mu.Unlock()
}

func (s *resolutionFailureRecorder) counts() (records, clears int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records), len(s.clears)
}

func attachResolutionFailureStore(r *Resolver, recorder *resolutionFailureRecorder) {
	var store middleware.Store = recorder
	r.store.Store(&store)
}

func TestResolutionZoneFailureStoreGuardsAndClear(t *testing.T) {
	r := new(Resolver)
	recorder := new(resolutionFailureRecorder)
	attachResolutionFailureStore(r, recorder)
	q := dns.Question{Name: "www.child.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	r.recordResolutionZoneFailure(context.Background(), q, "child.example.", fatalError(errConnectionFailed))
	r.recordResolutionZoneFailure(context.Background(), q, "child.example.", middleware.ErrResolutionAttemptLimit)
	r.recordResolutionZoneFailure(context.Background(), q, "child.example.", middleware.ErrRecursionWorkLimit)
	r.recordResolutionZoneFailure(context.Background(), q, "child.example.", middleware.ErrMaxRecursion)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	r.recordResolutionZoneFailure(cancelled, q, "child.example.", fatalError(errConnectionFailed))
	r.recordResolutionZoneFailure(
		middleware.WithBestEffortRecursionWork(context.Background()),
		q,
		"child.example.",
		fatalError(errConnectionFailed),
	)
	r.clearResolutionZoneFailure(q, "child.example.")

	records, clears := recorder.counts()
	if records != 1 || clears != 1 {
		t.Fatalf("failure store records=%d clears=%d, want 1/1", records, clears)
	}
}

func TestHandleLookupErrorRecordsOnlyTerminalAuthorityFailure(t *testing.T) {
	r := new(Resolver)
	recorder := new(resolutionFailureRecorder)
	attachResolutionFailureStore(r, recorder)
	req := new(dns.Msg)
	req.SetQuestion("www.child.example.", dns.TypeA)
	rs := &resolveState{
		req:     req,
		servers: &authority.Servers{Zone: "child.example."},
	}

	_, err := r.handleLookupError(
		context.Background(),
		fatalError(errConnectionFailed),
		rs,
		req,
		false,
	)
	if err == nil {
		t.Fatal("handleLookupError unexpectedly swallowed terminal network failure")
	}
	records, _ := recorder.counts()
	if records != 1 {
		t.Fatalf("terminal authority failure records = %d, want 1", records)
	}
	errorCount := atomic.LoadUint32(&rs.servers.ErrorCount)

	ordinaryErr := errors.New("ordinary resolver error")
	_, gotErr := r.handleLookupError(
		context.Background(),
		ordinaryErr,
		rs,
		req,
		false,
	)
	if !errors.Is(gotErr, ordinaryErr) {
		t.Fatalf("ordinary error = %v, want %v", gotErr, ordinaryErr)
	}
	records, _ = recorder.counts()
	if records != 1 {
		t.Fatalf("ordinary resolver error created zone failure state: records=%d", records)
	}
	if got := atomic.LoadUint32(&rs.servers.ErrorCount); got != errorCount {
		t.Fatalf("ordinary resolver error incremented authority error count: got %d want %d", got, errorCount)
	}

	nsLookupCtx := context.WithValue(context.Background(), contextKeyNSL, struct{}{})
	_, _ = r.handleLookupError(
		nsLookupCtx,
		fatalError(errConnectionFailed),
		rs,
		req,
		false,
	)
	records, _ = recorder.counts()
	if records != 1 {
		t.Fatalf("NS-address child lookup created zone failure state: records=%d", records)
	}
}

func TestResolveUpdatesZoneFailureStateFromAuthorityResponse(t *testing.T) {
	tests := []struct {
		name        string
		response    func(dns.Question) *dns.Msg
		wantRecords int
		wantClears  int
	}{
		{
			name: "useful answer clears",
			response: func(q dns.Question) *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.IPv4(192, 0, 2, 90),
					}},
				}
			},
			wantClears: 1,
		},
		{
			name: "terminal server failure records",
			response: func(dns.Question) *dns.Msg {
				return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
			},
			wantRecords: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := startAttackWireRecorder(t, tt.response)
			servers := &authority.Servers{
				Zone: "example.",
				List: []*authority.Server{
					authority.NewServer(wire.addr(), authority.IPv4),
				},
			}
			r := newAttackHarnessResolver(servers)
			recorder := new(resolutionFailureRecorder)
			attachResolutionFailureStore(r, recorder)
			req := new(dns.Msg)
			req.SetQuestion("www.example.", dns.TypeA)

			resp, err := r.Resolve(context.Background(), req, servers, false, 5, 0, true, nil)
			if err != nil || resp == nil {
				t.Fatalf("Resolve = resp:%#v err:%v", resp, err)
			}
			records, clears := recorder.counts()
			if records != tt.wantRecords || clears != tt.wantClears {
				t.Fatalf("failure state records=%d clears=%d, want %d/%d",
					records, clears, tt.wantRecords, tt.wantClears)
			}
		})
	}
}

func TestInvalidReferralDoesNotClearZoneFailureState(t *testing.T) {
	wire := startAttackWireRecorder(t, func(dns.Question) *dns.Msg {
		return &dns.Msg{Ns: []dns.RR{
			testNS("child.example.", "ns.child.example.", dns.ClassINET),
			testNS("sibling.example.", "ns.evil.example.", dns.ClassINET),
		}}
	})
	servers := &authority.Servers{
		Zone: "example.",
		List: []*authority.Server{
			authority.NewServer(wire.addr(), authority.IPv4),
		},
	}
	r := newAttackHarnessResolver(servers)
	recorder := new(resolutionFailureRecorder)
	attachResolutionFailureStore(r, recorder)
	req := new(dns.Msg)
	req.SetQuestion("www.child.example.", dns.TypeA)

	resp, err := r.Resolve(context.Background(), req, servers, false, 5, 0, true, nil)
	if resp != nil || !errors.Is(err, errParentDetection) {
		t.Fatalf("invalid referral Resolve = resp:%#v err:%v, want errParentDetection", resp, err)
	}
	_, clears := recorder.counts()
	if clears != 0 {
		t.Fatalf("invalid referral cleared zone failure state %d times", clears)
	}
}

func TestProcessDelegationRecordsUnreachableChildZone(t *testing.T) {
	r := newAttackHarnessResolver(&authority.Servers{Zone: "example."})
	installAttackQueryer(r, &attackAddressOracle{answers: map[string]net.IP{}})
	recorder := new(resolutionFailureRecorder)
	attachResolutionFailureStore(r, recorder)

	req := new(dns.Msg)
	req.SetQuestion("www.child.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Ns = []dns.RR{
		testNS("child.example.", "ns.child.example.", dns.ClassINET),
	}
	info := r.extractDelegationInfo(resp)
	rs := &resolveState{
		req:      req,
		servers:  &authority.Servers{Zone: "example."},
		depth:    5,
		level:    1,
		parentDS: nil,
	}

	_, err := r.processDelegation(context.Background(), rs, resp, info, false)
	if !errors.Is(err, errNoReachableAuth) {
		t.Fatalf("processDelegation error = %v, want errNoReachableAuth", err)
	}
	records, clears := recorder.counts()
	if records != 1 || clears != 1 {
		t.Fatalf("unreachable child state records=%d clears=%d, want child record + parent clear", records, clears)
	}
	recorder.mu.Lock()
	recordedZone := recorder.records[0]
	clearedZone := recorder.clears[0]
	recorder.mu.Unlock()
	if recordedZone != "child.example." {
		t.Fatalf("recorded zone = %q, want child.example.", recordedZone)
	}
	if clearedZone != "example." {
		t.Fatalf("cleared zone = %q, want useful parent authority example.", clearedZone)
	}
}

func TestLookupV4NssAttemptLimitRemainsTupleLocal(t *testing.T) {
	r := newAttackHarnessResolver(&authority.Servers{Zone: "example."})
	queryer := new(selectiveNSAddressQueryer)
	installAttackQueryer(r, queryer)
	q := dns.Question{Name: "child.example.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	servers := &authority.Servers{Zone: q.Name}
	hosts := hostSet{
		"limited.child.example.": {},
		"healthy.child.example.": {},
	}

	err := r.lookupV4Nss(
		context.Background(),
		q,
		servers,
		internalcache.Key(q),
		nil,
		make(hostSet),
		hosts,
		false,
		time.Now().Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("lookupV4Nss stopped after one tuple limit: %v", err)
	}
	if queryer.calls.Load() != 2 || len(servers.List) != 1 {
		t.Fatalf("NS lookup calls=%d servers=%d, want 2/1", queryer.calls.Load(), len(servers.List))
	}

	allLimited := new(selectiveNSAddressQueryer)
	allLimited.failAll = true
	rAllLimited := newAttackHarnessResolver(&authority.Servers{Zone: "example."})
	installAttackQueryer(rAllLimited, allLimited)
	empty := &authority.Servers{Zone: q.Name}
	err = rAllLimited.lookupV4Nss(
		context.Background(),
		q,
		empty,
		internalcache.Key(q),
		nil,
		make(hostSet),
		hosts,
		false,
		time.Now().Add(time.Minute),
	)
	if !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("all tuple-limited lookup error = %v, want ErrResolutionAttemptLimit", err)
	}

	maxQueryer := &resolverErrorQueryer{err: middleware.ErrMaxRecursion}
	rMax := newAttackHarnessResolver(&authority.Servers{Zone: "example."})
	installAttackQueryer(rMax, maxQueryer)
	err = rMax.lookupV4Nss(
		context.Background(),
		q,
		&authority.Servers{Zone: q.Name},
		internalcache.Key(q),
		nil,
		make(hostSet),
		hosts,
		false,
		time.Now().Add(time.Minute),
	)
	if !errors.Is(err, middleware.ErrMaxRecursion) {
		t.Fatalf("queryer recursion error = %v, want ErrMaxRecursion", err)
	}
	if got := maxQueryer.calls.Load(); got != 1 {
		t.Fatalf("queryer recursion calls = %d, want immediate stop after 1", got)
	}
}

func (c *attemptGuardSignalContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.ready) })
	return c.Context.Done()
}

func TestResolutionAttemptSingleflightFollowerRegroups(t *testing.T) {
	wire := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 61),
			}},
		}
	})
	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	r.maxConcurrent = make(chan struct{}, 1)
	r.maxConcurrent <- struct{}{} // hold the leader before queryServer starts

	server := authority.NewServer(wire.addr(), authority.IPv4)
	servers := &authority.Servers{Zone: ".", List: []*authority.Server{server}}
	req := new(dns.Msg)
	req.SetQuestion("singleflight-guard.example.", dns.TypeA)

	leaderBase, leaderGuard := middleware.EnsureResolutionAttemptGuard(context.Background())
	for range 3 {
		if err := leaderGuard.Begin(req.Question[0], server.Addr, "udp"); err != nil {
			t.Fatal(err)
		}
	}
	leaderReady := make(chan struct{})
	leaderCtx := &attemptGuardSignalContext{Context: leaderBase, ready: leaderReady}

	type result struct {
		resp *dns.Msg
		err  error
	}
	leaderDone := make(chan result, 1)
	go func() {
		resp, err := r.groupLookup(
			leaderCtx,
			&resolveState{req: req, requestID: req.Id},
			req,
			servers,
		)
		leaderDone <- result{resp: resp, err: err}
	}()
	select {
	case <-leaderReady:
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not reach the held lookup")
	}

	followerReq := req.Copy()
	followerReq.Id++
	followerBase, _ := middleware.EnsureResolutionAttemptGuard(context.Background())
	followerReady := make(chan struct{})
	followerCtx := &attemptGuardSignalContext{Context: followerBase, ready: followerReady}
	followerDone := make(chan result, 1)
	go func() {
		resp, err := r.groupLookup(
			followerCtx,
			&resolveState{req: followerReq, requestID: followerReq.Id},
			followerReq,
			servers,
		)
		followerDone <- result{resp: resp, err: err}
	}()
	select {
	case <-followerReady:
	case <-time.After(5 * time.Second):
		t.Fatal("follower did not join the in-flight generation")
	}

	<-r.maxConcurrent

	select {
	case got := <-leaderDone:
		if got.resp != nil || !errors.Is(got.err, middleware.ErrResolutionAttemptLimit) {
			t.Fatalf("leader = resp:%#v err:%v, want request-local guard error", got.resp, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not finish")
	}
	select {
	case got := <-followerDone:
		if got.err != nil || got.resp == nil || len(got.resp.Answer) != 1 || got.resp.Id != followerReq.Id {
			t.Fatalf("follower inherited leader guard: resp:%#v err:%v", got.resp, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follower did not regroup")
	}
	if got := wire.count(); got != 1 {
		t.Fatalf("wire attempts = %d, want one regrouped follower attempt", got)
	}
}

func TestLookupRejectsBadReferralAndKeepsHealthyAuthority(t *testing.T) {
	tests := []struct {
		name string
		bad  []dns.RR
	}{
		{
			name: "mixed owner",
			bad: []dns.RR{
				testNS("child.example.", "ns.bad.example.", dns.ClassINET),
				testNS("sibling.example.", "ns.evil.example.", dns.ClassINET),
			},
		},
		{
			name: "unrelated deeper owner",
			bad: []dns.RR{
				testNS("sibling.example.", "ns.evil.example.", dns.ClassINET),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goodGate := make(chan struct{})
			var gateOnce sync.Once
			releaseGood := func() { gateOnce.Do(func() { close(goodGate) }) }
			t.Cleanup(releaseGood)

			badWire := startAttackWireRecorder(t, func(dns.Question) *dns.Msg {
				return &dns.Msg{Ns: tt.bad}
			})
			goodWire := startAttackWireRecorder(t, func(dns.Question) *dns.Msg {
				<-goodGate
				return &dns.Msg{Ns: []dns.RR{
					testNS("child.example.", "ns.good.example.", dns.ClassINET),
				}}
			})
			r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
			badServer := authority.NewServer(badWire.addr(), authority.IPv4)
			goodServer := authority.NewServer(goodWire.addr(), authority.IPv4)
			servers := &authority.Servers{
				Zone: "example.",
				List: []*authority.Server{badServer, goodServer},
			}
			req := new(dns.Msg)
			req.SetQuestion("www.child.example.", dns.TypeA)
			ctx, _ := middleware.EnsureResolutionAttemptGuard(context.Background())

			type lookupResult struct {
				resp *dns.Msg
				err  error
			}
			done := make(chan lookupResult, 1)
			go func() {
				resp, err := r.lookup(ctx, &resolveState{req: req, requestID: req.Id}, req, servers)
				done <- lookupResult{resp: resp, err: err}
			}()

			deadline := time.NewTimer(5 * time.Second)
			ticker := time.NewTicker(time.Millisecond)
			defer deadline.Stop()
			defer ticker.Stop()
		waitForPenalty:
			for {
				select {
				case got := <-done:
					t.Fatalf("lookup accepted bad referral before healthy response: resp:%#v err:%v", got.resp, got.err)
				case <-ticker.C:
					if atomic.LoadInt64(&badServer.Count) >= 2 {
						break waitForPenalty
					}
				case <-deadline.C:
					t.Fatal("bad referral was not rejected and penalized")
				}
			}

			releaseGood()
			select {
			case got := <-done:
				if got.err != nil || got.resp == nil || len(got.resp.Ns) != 1 {
					t.Fatalf("healthy referral = resp:%#v err:%v", got.resp, got.err)
				}
				ns, ok := got.resp.Ns[0].(*dns.NS)
				if !ok || ns.Ns != "ns.good.example." {
					t.Fatalf("winning referral = %#v, want healthy authority", got.resp.Ns)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("lookup did not return healthy authority")
			}
			if badWire.count() != 1 || goodWire.count() != 1 {
				t.Fatalf("wire counts bad=%d good=%d, want 1 each", badWire.count(), goodWire.count())
			}
		})
	}
}

func TestProcessDelegationRejectsMixedOwnerFallback(t *testing.T) {
	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	req := new(dns.Msg)
	req.SetQuestion("www.child.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Ns = []dns.RR{
		testNS("child.example.", "ns.good.example.", dns.ClassINET),
		testNS("sibling.example.", "ns.evil.example.", dns.ClassINET),
	}
	info := r.extractDelegationInfo(resp)
	if !info.incoherent {
		t.Fatal("mixed-owner Authority section was not marked incoherent")
	}
	rs := &resolveState{
		req:     req,
		servers: &authority.Servers{Zone: "example."},
	}

	_, err := r.processDelegation(context.Background(), rs, resp, info, false)
	if !errors.Is(err, errParentDetection) {
		t.Fatalf("processDelegation error = %v, want errParentDetection", err)
	}
}

func testNS(owner, target string, class uint16) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: class, Ttl: 60},
		Ns:  target,
	}
}
