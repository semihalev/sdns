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
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

type recursionDebitingQueryer struct {
	next middleware.Queryer
}

func (q recursionDebitingQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if err := middleware.DebitRecursionWork(ctx, middleware.RecursionWorkInternalQuery); err != nil {
		return nil, err
	}
	return q.next.Query(ctx, req)
}

func enforceWorkLedger(maxOutbound, maxInternal uint32) *middleware.RecursionWorkLedger {
	return middleware.NewRecursionWorkLedger(middleware.RecursionWorkPolicy{
		Mode:               middleware.RecursionWorkEnforce,
		MaxOutboundQueries: maxOutbound,
		MaxInternalQueries: maxInternal,
	})
}

type singleflightRetryBarrierContext struct {
	context.Context

	firstOnce sync.Once
	retryOnce sync.Once

	firstArrivals *atomic.Int32
	retryArrivals *atomic.Int32
	participants  int32
	releaseFirst  func()
	releaseRetry  func()
}

func (c *singleflightRetryBarrierContext) Done() <-chan struct{} {
	firstCall := false
	c.firstOnce.Do(func() {
		firstCall = true
		if c.firstArrivals.Add(1) == c.participants {
			c.releaseFirst()
		}
	})
	if !firstCall {
		c.retryOnce.Do(func() {
			if c.retryArrivals.Add(1) == c.participants {
				c.releaseRetry()
			}
		})
	}
	return c.Context.Done()
}

type delayedFirstDoneContext struct {
	context.Context

	calls        atomic.Int32
	firstReady   chan struct{}
	releaseFirst <-chan struct{}
	retryOnce    sync.Once
	releaseRetry func()
}

func (c *delayedFirstDoneContext) Done() <-chan struct{} {
	if c.calls.Add(1) == 1 {
		close(c.firstReady)
		<-c.releaseFirst
	} else {
		c.retryOnce.Do(c.releaseRetry)
	}
	return c.Context.Done()
}

func TestRecursionWorkNXNSInternalBudget(t *testing.T) {
	const (
		nsCount = 12
		cap     = 4
	)

	hosts := make(hostSet, nsCount)
	for i := 0; i < nsCount; i++ {
		name := dns.Fqdn("ns" + string(rune('a'+i)) + ".budget.test")
		hosts[name] = struct{}{}
	}

	// The NXNS shape: one referral naming many glue-less hosts. The walk
	// resolves synchronously only until two hosts yield addresses — the
	// failover floor — so a roster that resolves costs the request two
	// internal queries; the rest is lane work that never touches this
	// request's budget.
	t.Run("a resolving roster costs the two-host floor", func(t *testing.T) {
		addresses := make(map[string]net.IP, nsCount)
		i := byte(1)
		for name := range hosts {
			addresses[name] = net.IPv4(192, 0, 2, i)
			i++
		}
		r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
		oracle := &attackAddressOracle{answers: addresses, record: true}
		installAttackQueryer(r, recursionDebitingQueryer{next: oracle})

		ledger := enforceWorkLedger(128, cap)
		ctx := middleware.WithRecursionWork(context.Background(), ledger)
		q := dns.Question{Name: "victim.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
		authservers := &authority.Servers{Zone: "victim.test.", CheckingDisable: true}

		err := r.lookupV4Nss(ctx, q, authservers, internalcache.Key(q, true), nil,
			make(hostSet), hosts, true, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("lookupV4Nss error = %v, want one cheap success", err)
		}
		if got := oracle.count(); got != 2 {
			t.Fatalf("synchronous NS-address queries = %d, want the two-host floor", got)
		}
		if snapshot := ledger.Snapshot(); snapshot.InternalQueries != 2 {
			t.Fatalf("internal ledger snapshot = %+v, want two queries charged", snapshot)
		}
	})

	// A roster that never yields an address keeps the walk resolving
	// synchronously, and the request budget still terminates it at the cap.
	t.Run("a barren roster still trips the request budget", func(t *testing.T) {
		r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
		oracle := &attackAddressOracle{answers: map[string]net.IP{}, record: true}
		installAttackQueryer(r, recursionDebitingQueryer{next: oracle})

		ledger := enforceWorkLedger(128, cap)
		ctx := middleware.WithRecursionWork(context.Background(), ledger)
		q := dns.Question{Name: "victim.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
		authservers := &authority.Servers{Zone: "victim.test.", CheckingDisable: true}

		err := r.lookupV4Nss(ctx, q, authservers, internalcache.Key(q, true), nil,
			make(hostSet), hosts, true, time.Now().Add(time.Minute))
		if !errors.Is(err, middleware.ErrRecursionWorkLimit) {
			t.Fatalf("lookupV4Nss error = %v, want recursion work limit", err)
		}
		if got := oracle.count(); got != cap {
			t.Fatalf("accepted NS-address child queries = %d, want exact cap %d", got, cap)
		}
		snapshot := ledger.Snapshot()
		if snapshot.InternalQueries != cap || !snapshot.InternalExhausted {
			t.Fatalf("internal ledger snapshot = %+v, want used=%d exhausted=true", snapshot, cap)
		}
	})
}

func TestRecursionWorkDetachedIPv6JobHasSharedBudget(t *testing.T) {
	const (
		nsCount = 8
		cap     = 3
	)

	hosts := make(hostSet, nsCount)
	for i := 0; i < nsCount; i++ {
		hosts[dns.Fqdn("nsv6"+string(rune('a'+i))+".budget.test")] = struct{}{}
	}

	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	r.glueV6 = internalcache.New(defaultCacheSize)
	oracle := &attackAddressOracle{record: true}
	installAttackQueryer(r, recursionDebitingQueryer{next: oracle})

	policy := middleware.RecursionWorkPolicy{
		Mode:               middleware.RecursionWorkEnforce,
		MaxOutboundQueries: 128,
		MaxInternalQueries: cap,
	}
	ctx, ledger := middleware.EnsureRecursionWork(context.Background(), policy)
	q := dns.Question{Name: "victim.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	authservers := &authority.Servers{Zone: "victim.test.", CheckingDisable: true}

	r.lookupV6Nss(ctx, q, authservers, make(hostSet), hosts, true)

	if got := oracle.count(); got != cap {
		t.Fatalf("accepted detached IPv6 child queries = %d, want exact cap %d", got, cap)
	}
	snapshot := ledger.Snapshot()
	if snapshot.InternalQueries != cap || !snapshot.InternalExhausted {
		t.Fatalf("detached IPv6 ledger snapshot = %+v, want used=%d exhausted=true", snapshot, cap)
	}
	if err := ledger.EnforcementError(); err != nil {
		t.Fatalf("best-effort detached job poisoned request tree: %v", err)
	}

	wire := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 31),
			}},
		}
	})
	requiredServers := &authority.Servers{
		Zone: ".",
		List: []*authority.Server{
			authority.NewServer(wire.addr(), authority.IPv4),
		},
	}
	req := new(dns.Msg)
	req.SetQuestion("required-after-optional.example.", dns.TypeA)

	resp, err := r.Resolve(ctx, req, requiredServers, false, 30, 0, false, nil)
	if err != nil {
		t.Fatalf("required resolution after optional rejection: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("required response = %#v, want one successful answer", resp)
	}
	if got := wire.count(); got != 1 {
		t.Fatalf("required wire attempts = %d, want 1", got)
	}
}

func TestRecursionWorkDNAMEBudgetPrecedesAliasDepth(t *testing.T) {
	const cap = 4

	r := &Resolver{dnssec: false}
	loop := &attackDNAMEQueryer{resolver: r}
	installAttackQueryer(r, recursionDebitingQueryer{next: loop})

	ledger := enforceWorkLedger(128, cap)
	ctx := middleware.WithRecursionWork(context.Background(), ledger)

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

	got, err := r.answer(ctx, req, resp, nil, "a.loop.test.")
	if !errors.Is(err, middleware.ErrRecursionWorkLimit) {
		t.Fatalf("DNAME loop error = %v, want recursion work limit", err)
	}
	if got != nil {
		t.Fatalf("DNAME budget returned partial response: %v", got)
	}
	if count := loop.count(); count != cap {
		t.Fatalf("accepted DNAME child queries = %d, want exact cap %d", count, cap)
	}
	if count := loop.count(); count >= maxDnameDepth {
		t.Fatalf("work budget did not precede maxDnameDepth: count=%d depth-cap=%d", count, maxDnameDepth)
	}
}

func TestRecursionWorkOutboundCapAppliesWithCD(t *testing.T) {
	wire := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 80),
			}},
		}
	})
	server := authority.NewServer(wire.addr(), authority.IPv4)

	for _, cd := range []bool{false, true} {
		t.Run(map[bool]string{false: "validation-enabled", true: "checking-disabled"}[cd], func(t *testing.T) {
			ledger := enforceWorkLedger(1, 32)
			r := &Resolver{
				cfg:        &config.Config{},
				netTimeout: time.Second,
			}
			req := new(dns.Msg)
			req.SetQuestion("cap.example.", dns.TypeA)
			req.CheckingDisabled = cd
			rs := &resolveState{req: req, requestID: req.Id, work: ledger}

			before := wire.count()
			resp, err := r.exchange(context.Background(), rs, nil, "udp", req, server, 0)
			if err != nil {
				t.Fatalf("first exchange error = %v", err)
			}
			if resp == nil || resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("first exchange response = %v, want success", resp)
			}

			_, err = r.exchange(context.Background(), rs, nil, "udp", req, server, 0)
			if !errors.Is(err, middleware.ErrRecursionWorkLimit) {
				t.Fatalf("second exchange error = %v, want recursion work limit", err)
			}
			if got := wire.count() - before; got != 1 {
				t.Fatalf("wire attempts with CD=%v = %d, want 1", cd, got)
			}
			if got := ledger.Snapshot().OutboundQueries; got != 1 {
				t.Fatalf("outbound ledger with CD=%v = %d, want 1", cd, got)
			}
		})
	}
}

func TestRecursionWorkOutboundRetryCap(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole: %v", err)
	}
	defer packet.Close()

	var received atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, dns.MaxMsgSize)
		for {
			if err := packet.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				return
			}
			if _, _, err := packet.ReadFrom(buf); err != nil {
				return
			}
			received.Add(1)
		}
	}()

	ledger := enforceWorkLedger(2, 32)
	r := &Resolver{
		cfg:        &config.Config{},
		netTimeout: 20 * time.Millisecond,
	}
	req := new(dns.Msg)
	req.SetQuestion("retry.example.", dns.TypeA)
	server := authority.NewServer(packet.LocalAddr().String(), authority.IPv4)
	rs := &resolveState{req: req, requestID: req.Id, work: ledger}

	_, err = r.exchange(context.Background(), rs, nil, "udp", req, server, 0)
	if !errors.Is(err, middleware.ErrRecursionWorkLimit) {
		t.Fatalf("retry exchange error = %v, want recursion work limit", err)
	}
	if got := ledger.Snapshot().OutboundQueries; got != 2 {
		t.Fatalf("accepted retry attempts = %d, want exact cap 2", got)
	}

	deadline := time.Now().Add(time.Second)
	for received.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := received.Load(); got != 2 {
		t.Fatalf("wire retry attempts = %d, want 2", got)
	}

	_ = packet.Close()
	<-done
}

func TestRecursionWorkSingleflightFollowersRegroupOnLeaderLimit(t *testing.T) {
	const followerCount = int32(4)

	testTimeout := time.After(10 * time.Second)
	firstArrived := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondArrived := make(chan struct{})
	releaseRetry := make(chan struct{})
	var releaseFirstOnce, releaseRetryOnce sync.Once
	closeFirst := func() {
		releaseFirstOnce.Do(func() { close(releaseFirst) })
	}
	closeRetry := func() {
		releaseRetryOnce.Do(func() { close(releaseRetry) })
	}
	t.Cleanup(closeFirst)
	t.Cleanup(closeRetry)

	var calls atomic.Int32
	wire := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		switch calls.Add(1) {
		case 1:
			close(firstArrived)
			<-releaseFirst
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeFormatError}}
		case 2:
			close(secondArrived)
			<-releaseRetry
		}
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 30),
			}},
		}
	})

	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	servers := &authority.Servers{
		Zone: ".",
		List: []*authority.Server{
			authority.NewServer(wire.addr(), authority.IPv4),
		},
	}
	req := new(dns.Msg)
	req.SetQuestion("singleflight-budget.example.", dns.TypeA)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	type lookupOutcome struct {
		index int
		id    uint16
		resp  *dns.Msg
		err   error
	}
	leaderLedger := enforceWorkLedger(1, 32)
	leaderDone := make(chan lookupOutcome, 1)
	go func() {
		resp, err := r.groupLookup(
			context.Background(),
			&resolveState{req: req, requestID: req.Id, work: leaderLedger},
			req,
			servers,
			false,
		)
		leaderDone <- lookupOutcome{resp: resp, err: err}
	}()
	select {
	case <-firstArrived:
	case <-testTimeout:
		t.Fatal("timed out waiting for first singleflight leader")
	}

	var firstArrivals, retryArrivals atomic.Int32
	followerLedgers := make([]*middleware.RecursionWorkLedger, followerCount)
	followerDone := make(chan lookupOutcome, followerCount)
	for i := range int(followerCount) {
		followerLedgers[i] = enforceWorkLedger(4, 32)
		followerReq := req.Copy()
		followerReq.Id = uint16(100 + i)
		followerCtx := &singleflightRetryBarrierContext{
			Context:       context.Background(),
			firstArrivals: &firstArrivals,
			retryArrivals: &retryArrivals,
			participants:  followerCount,
			releaseFirst:  closeFirst,
			releaseRetry:  closeRetry,
		}
		go func(index int, ctx context.Context, request *dns.Msg, ledger *middleware.RecursionWorkLedger) {
			resp, err := r.groupLookup(
				ctx,
				&resolveState{req: request, requestID: request.Id, work: ledger},
				request,
				servers,
				false,
			)
			followerDone <- lookupOutcome{index: index, id: request.Id, resp: resp, err: err}
		}(i, followerCtx, followerReq, followerLedgers[i])
	}

	select {
	case <-secondArrived:
	case <-testTimeout:
		t.Fatal("timed out waiting for regrouped singleflight leader")
	}
	for range followerCount {
		var outcome lookupOutcome
		select {
		case outcome = <-followerDone:
		case <-testTimeout:
			t.Fatal("timed out waiting for regrouped follower result")
		}
		if outcome.err != nil {
			t.Fatalf("follower %d inherited leader policy error: %v", outcome.index, outcome.err)
		}
		if outcome.resp == nil || outcome.resp.Id != outcome.id ||
			outcome.resp.Rcode != dns.RcodeSuccess || len(outcome.resp.Answer) != 1 {
			t.Fatalf("follower %d response = %#v, want successful answer with id %d",
				outcome.index, outcome.resp, outcome.id)
		}
	}

	var leader lookupOutcome
	select {
	case leader = <-leaderDone:
	case <-testTimeout:
		t.Fatal("timed out waiting for exhausted first leader")
	}
	if leader.resp != nil || !errors.Is(leader.err, middleware.ErrRecursionWorkLimit) {
		t.Fatalf("leader outcome = resp:%#v err:%v, want recursion work limit", leader.resp, leader.err)
	}
	if snapshot := leaderLedger.Snapshot(); snapshot.OutboundQueries != 1 || !snapshot.OutboundExhausted {
		t.Fatalf("leader ledger = %+v, want outbound=1 exhausted=true", snapshot)
	}
	var followerOutbound uint32
	for i, ledger := range followerLedgers {
		snapshot := ledger.Snapshot()
		followerOutbound += snapshot.OutboundQueries
		if snapshot.OutboundExhausted {
			t.Fatalf("follower %d ledger exhausted: %+v", i, snapshot)
		}
	}
	if followerOutbound != 1 {
		t.Fatalf("follower outbound work = %d, want one regrouped attempt", followerOutbound)
	}
	if got := wire.count(); got != 2 {
		t.Fatalf("wire attempts = %d, want one leader plus one regrouped follower attempt", got)
	}
}

func TestRecursionWorkSingleflightHealthyFollowerRegroupsPastLowBudgetLeader(t *testing.T) {
	testTimeout := time.After(10 * time.Second)

	firstArrived := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondArrived := make(chan struct{})
	releaseSecond := make(chan struct{})
	releaseHealthy := make(chan struct{})
	var firstOnce, secondOnce, healthyOnce sync.Once
	closeFirst := func() {
		firstOnce.Do(func() { close(releaseFirst) })
	}
	closeSecond := func() {
		secondOnce.Do(func() { close(releaseSecond) })
	}
	closeHealthy := func() {
		healthyOnce.Do(func() { close(releaseHealthy) })
	}
	t.Cleanup(closeFirst)
	t.Cleanup(closeSecond)
	t.Cleanup(closeHealthy)

	var calls atomic.Int32
	wire := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		switch calls.Add(1) {
		case 1:
			close(firstArrived)
			<-releaseFirst
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeFormatError}}
		case 2:
			close(secondArrived)
			<-releaseSecond
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeFormatError}}
		default:
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Authoritative: true},
				Answer: []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.IPv4(192, 0, 2, 32),
				}},
			}
		}
	})

	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	servers := &authority.Servers{
		Zone: ".",
		List: []*authority.Server{
			authority.NewServer(wire.addr(), authority.IPv4),
		},
	}
	baseReq := new(dns.Msg)
	baseReq.SetQuestion("heterogeneous-singleflight-budget.example.", dns.TypeA)
	baseReq.SetEdns0(dnsutil.DefaultMsgSize, true)

	type lookupOutcome struct {
		resp *dns.Msg
		err  error
	}
	firstLedger := enforceWorkLedger(1, 32)
	firstDone := make(chan lookupOutcome, 1)
	go func() {
		resp, err := r.groupLookup(
			context.Background(),
			&resolveState{req: baseReq, requestID: baseReq.Id, work: firstLedger},
			baseReq,
			servers,
			false,
		)
		firstDone <- lookupOutcome{resp: resp, err: err}
	}()
	select {
	case <-firstArrived:
	case <-testTimeout:
		t.Fatal("timed out waiting for first low-budget leader")
	}

	healthyReq := baseReq.Copy()
	healthyReq.Id = 300
	healthyLedger := enforceWorkLedger(4, 32)
	healthyFirstReady := make(chan struct{})
	healthyCtx := &delayedFirstDoneContext{
		Context:      context.Background(),
		firstReady:   healthyFirstReady,
		releaseFirst: releaseHealthy,
		releaseRetry: closeSecond,
	}
	healthyDone := make(chan lookupOutcome, 1)
	go func() {
		resp, err := r.groupLookup(
			healthyCtx,
			&resolveState{req: healthyReq, requestID: healthyReq.Id, work: healthyLedger},
			healthyReq,
			servers,
			false,
		)
		healthyDone <- lookupOutcome{resp: resp, err: err}
	}()
	select {
	case <-healthyFirstReady:
	case <-testTimeout:
		t.Fatal("timed out waiting for healthy follower to join first group")
	}

	lowReq := baseReq.Copy()
	lowReq.Id = 200
	lowLedger := enforceWorkLedger(1, 32)
	lowCtx := &runOnDoneContext{
		Context: context.Background(),
		run:     closeFirst,
	}
	lowDone := make(chan lookupOutcome, 1)
	go func() {
		resp, err := r.groupLookup(
			lowCtx,
			&resolveState{req: lowReq, requestID: lowReq.Id, work: lowLedger},
			lowReq,
			servers,
			false,
		)
		lowDone <- lookupOutcome{resp: resp, err: err}
	}()

	select {
	case <-secondArrived:
	case <-testTimeout:
		t.Fatal("timed out waiting for low-budget regroup leader")
	}
	closeHealthy()

	var healthy lookupOutcome
	select {
	case healthy = <-healthyDone:
	case <-testTimeout:
		t.Fatal("timed out waiting for healthy regrouped follower")
	}
	if healthy.err != nil {
		t.Fatalf("healthy follower inherited regroup leader policy error: %v", healthy.err)
	}
	if healthy.resp == nil || healthy.resp.Id != healthyReq.Id ||
		healthy.resp.Rcode != dns.RcodeSuccess || len(healthy.resp.Answer) != 1 {
		t.Fatalf("healthy follower response = %#v, want successful answer with id %d",
			healthy.resp, healthyReq.Id)
	}

	var low lookupOutcome
	select {
	case low = <-lowDone:
	case <-testTimeout:
		t.Fatal("timed out waiting for low-budget regroup leader")
	}
	if low.resp != nil || !errors.Is(low.err, middleware.ErrRecursionWorkLimit) {
		t.Fatalf("low-budget regroup outcome = resp:%#v err:%v, want work limit", low.resp, low.err)
	}

	var first lookupOutcome
	select {
	case first = <-firstDone:
	case <-testTimeout:
		t.Fatal("timed out waiting for first low-budget leader result")
	}
	if first.resp != nil || !errors.Is(first.err, middleware.ErrRecursionWorkLimit) {
		t.Fatalf("first leader outcome = resp:%#v err:%v, want work limit", first.resp, first.err)
	}

	if snapshot := firstLedger.Snapshot(); snapshot.OutboundQueries != 1 || !snapshot.OutboundExhausted {
		t.Fatalf("first leader ledger = %+v, want outbound=1 exhausted=true", snapshot)
	}
	if snapshot := lowLedger.Snapshot(); snapshot.OutboundQueries != 1 || !snapshot.OutboundExhausted {
		t.Fatalf("regroup leader ledger = %+v, want outbound=1 exhausted=true", snapshot)
	}
	if snapshot := healthyLedger.Snapshot(); snapshot.OutboundQueries != 1 || snapshot.OutboundExhausted {
		t.Fatalf("healthy follower ledger = %+v, want outbound=1 exhausted=false", snapshot)
	}
	if got := wire.count(); got != 3 {
		t.Fatalf("wire attempts = %d, want one attempt from each successive leader", got)
	}
}
