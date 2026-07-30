package resolver

import (
	"context"
	"errors"
	"net"
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

func TestRecursionWorkNXNSInternalBudget(t *testing.T) {
	const (
		nsCount = 12
		cap     = 4
	)

	hosts := make(hostSet, nsCount)
	addresses := make(map[string]net.IP, nsCount)
	for i := 0; i < nsCount; i++ {
		name := dns.Fqdn("ns" + string(rune('a'+i)) + ".budget.test")
		hosts[name] = struct{}{}
		addresses[name] = net.IPv4(192, 0, 2, byte(i+1))
	}

	r := newAttackHarnessResolver(&authority.Servers{Zone: "."})
	oracle := &attackAddressOracle{answers: addresses, record: true}
	installAttackQueryer(r, recursionDebitingQueryer{next: oracle})

	ledger := enforceWorkLedger(128, cap)
	ctx := middleware.WithRecursionWork(context.Background(), ledger)
	q := dns.Question{Name: "victim.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	authservers := &authority.Servers{Zone: "victim.test.", CheckingDisable: true}

	err := r.lookupV4Nss(
		ctx,
		q,
		authservers,
		internalcache.Key(q, true),
		nil,
		make(hostSet),
		hosts,
		true,
		time.Now().Add(time.Minute),
	)
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
			resp, err := r.exchange(context.Background(), rs, "udp", req, server, 0)
			if err != nil {
				t.Fatalf("first exchange error = %v", err)
			}
			if resp == nil || resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("first exchange response = %v, want success", resp)
			}

			_, err = r.exchange(context.Background(), rs, "udp", req, server, 0)
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

	_, err = r.exchange(context.Background(), rs, "udp", req, server, 0)
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

func TestRecursionWorkSingleflightFollowerUsesOwnLedger(t *testing.T) {
	firstArrived := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	wire := startAttackWireRecorder(t, func(q dns.Question) *dns.Msg {
		if calls.Add(1) == 1 {
			close(firstArrived)
			<-releaseFirst
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeFormatError}}
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
		resp *dns.Msg
		err  error
	}
	leaderLedger := enforceWorkLedger(1, 32)
	leaderDone := make(chan lookupOutcome, 1)
	go func() {
		resp, err := r.groupLookup(
			context.Background(),
			&resolveState{req: req, requestID: req.Id, work: leaderLedger},
			req,
			servers,
		)
		leaderDone <- lookupOutcome{resp: resp, err: err}
	}()
	<-firstArrived

	followerLedger := enforceWorkLedger(4, 32)
	followerCtx := &releaseOnDoneContext{
		Context: context.Background(),
		release: releaseFirst,
	}
	followerResp, followerErr := r.groupLookup(
		followerCtx,
		&resolveState{req: req, requestID: req.Id, work: followerLedger},
		req,
		servers,
	)
	if followerErr != nil {
		t.Fatalf("follower inherited leader policy error: %v", followerErr)
	}
	if followerResp == nil || followerResp.Rcode != dns.RcodeSuccess || len(followerResp.Answer) != 1 {
		t.Fatalf("follower response = %#v, want successful independent lookup", followerResp)
	}

	leader := <-leaderDone
	if leader.resp != nil || !errors.Is(leader.err, middleware.ErrRecursionWorkLimit) {
		t.Fatalf("leader outcome = resp:%#v err:%v, want recursion work limit", leader.resp, leader.err)
	}
	if snapshot := leaderLedger.Snapshot(); snapshot.OutboundQueries != 1 || !snapshot.OutboundExhausted {
		t.Fatalf("leader ledger = %+v, want outbound=1 exhausted=true", snapshot)
	}
	if snapshot := followerLedger.Snapshot(); snapshot.OutboundQueries != 1 || snapshot.OutboundExhausted {
		t.Fatalf("follower ledger = %+v, want outbound=1 exhausted=false", snapshot)
	}
	if got := wire.count(); got != 2 {
		t.Fatalf("wire attempts = %d, want one leader plus one follower attempt", got)
	}
}
