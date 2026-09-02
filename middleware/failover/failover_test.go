package failover

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	m := new(dns.Msg)
	m.SetRcode(req.Msg(), dns.RcodeServerFailure)

	_ = w.WriteMsg(m)
}

func (d *dummy) Name() string { return "dummy" }

func Test_Failover(t *testing.T) {
	middleware.Reset()
	t.Cleanup(middleware.Reset)

	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	// A fallback that answers, one that refuses immediately, and one that is
	// not an address at all. The pair used to be a black-holed IPv6 address
	// and 8.8.8.8, which made this test both slow, the black hole had to
	// time out, and dependent on Google answering for example.com.
	answering, _, stop := startFailoverRcodeServer(t, dns.RcodeSuccess)
	defer stop()
	vacant := vacantLoopbackAddr(t)

	cfg := new(config.Config)
	cfg.FallbackServers = []string{vacant, answering, "1"}

	middleware.Register("failover", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	f := middleware.Get("failover").(*Failover)
	if !reflect.DeepEqual("failover", f.Name()) {
		t.Errorf("f.Name() = %v, want %v", f.Name(), "failover")
	}

	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	ch.Request = middleware.NewRequest(req)

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(dns.RcodeServerFailure, mw.Rcode()) {
		t.Errorf("mw.Rcode() = %v, want %v", mw.Rcode(), dns.RcodeServerFailure)
	}

	req.RecursionDesired = true

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(mw.Rcode(), dns.RcodeSuccess) {
		t.Errorf("dns.RcodeSuccess = %v, want %v", dns.RcodeSuccess, mw.Rcode())
	}

	f.servers = []string{}

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(mw.Rcode(), dns.RcodeServerFailure) {
		t.Errorf("dns.RcodeServerFailure = %v, want %v", dns.RcodeServerFailure, mw.Rcode())
	}

	// A refused port rather than a black hole: the assertion is that an
	// unusable fallback yields SERVFAIL, not that we can wait out a timeout.
	f.servers = []string{vacant}

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(mw.Rcode(), dns.RcodeServerFailure) {
		t.Errorf("dns.RcodeServerFailure = %v, want %v", dns.RcodeServerFailure, mw.Rcode())
	}
}

func TestFailoverRecursionWorkBoundsFallbackPool(t *testing.T) {
	badAddr, badCalls, stopBad := startFailoverServer(t, true)
	defer stopBad()
	goodAddr, goodCalls, stopGood := startFailoverServer(t, false)
	defer stopGood()

	tests := []struct {
		name         string
		mode         middleware.RecursionWorkMode
		wantRcode    int
		wantGood     int32
		wantOutbound uint32
		wantEDE      bool
	}{
		{
			name:         "enforce rejects second fallback at cap",
			mode:         middleware.RecursionWorkEnforce,
			wantRcode:    dns.RcodeServerFailure,
			wantGood:     0,
			wantOutbound: 1,
			wantEDE:      true,
		},
		{
			name:         "shadow observes but preserves fallback",
			mode:         middleware.RecursionWorkShadow,
			wantRcode:    dns.RcodeSuccess,
			wantGood:     1,
			wantOutbound: 2,
			wantEDE:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeBad := badCalls.Load()
			beforeGood := goodCalls.Load()

			ledger := middleware.NewRecursionWorkLedger(middleware.RecursionWorkPolicy{
				Mode:               tt.mode,
				MaxOutboundQueries: 1,
				MaxInternalQueries: 32,
			})
			ctx := middleware.WithRecursionWork(context.Background(), ledger)
			f := &Failover{servers: []string{badAddr, goodAddr}}

			req := new(dns.Msg)
			req.SetQuestion("fallback.example.", dns.TypeA)
			req.SetEdns0(1232, true)
			req.RecursionDesired = true
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})
			ch.Reset(mw, req)
			ch.Next(ctx)

			resp := mw.Msg()
			if resp == nil || resp.Rcode != tt.wantRcode {
				t.Fatalf("response = %#v, want rcode %s", resp, dns.RcodeToString[tt.wantRcode])
			}
			if got := badCalls.Load() - beforeBad; got != 1 {
				t.Fatalf("first fallback calls = %d, want 1", got)
			}
			if got := goodCalls.Load() - beforeGood; got != tt.wantGood {
				t.Fatalf("second fallback calls = %d, want %d", got, tt.wantGood)
			}

			snapshot := ledger.Snapshot()
			if snapshot.OutboundQueries != tt.wantOutbound || !snapshot.OutboundExhausted {
				t.Fatalf("ledger snapshot = %+v, want outbound=%d exhausted=true",
					snapshot, tt.wantOutbound)
			}
			ede := dnsutil.GetEDE(resp)
			if tt.wantEDE {
				if ede == nil ||
					ede.InfoCode != middleware.RecursionWorkEDECode ||
					ede.ExtraText != middleware.RecursionWorkEDEText {
					t.Fatalf("policy EDE = %+v, want code=%d text=%q",
						ede, middleware.RecursionWorkEDECode, middleware.RecursionWorkEDEText)
				}
			} else if ede != nil {
				t.Fatalf("shadow response unexpectedly carries EDE: %+v", ede)
			}
		})
	}
}

func TestFailoverResolutionAttemptGuardBoundsDuplicateEndpoints(t *testing.T) {
	addr, calls, stop := startFailoverServer(t, true)
	defer stop()

	f := &Failover{servers: []string{addr, addr, addr, addr, addr}}
	req := new(dns.Msg)
	req.SetQuestion("attempt-guard.example.", dns.TypeA)
	req.RecursionDesired = true
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})
	ch.Reset(mw, req)
	ctx := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	ch.Next(ctx)

	if got := calls.Load(); got != 3 {
		t.Fatalf("fallback wire attempts = %d, want 3", got)
	}
	if mw.Rcode() != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[mw.Rcode()])
	}
	if err := middleware.RequestLocalFailureForResponse(ctx, mw.Msg()); !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("all-tuples-blocked provenance = %v, want ErrResolutionAttemptLimit", err)
	}
}

func TestFailoverTriesNextServerAfterUnusableDNSResponse(t *testing.T) {
	badAddr, badCalls, stopBad := startFailoverRcodeServer(t, dns.RcodeServerFailure)
	defer stopBad()
	goodAddr, goodCalls, stopGood := startFailoverRcodeServer(t, dns.RcodeSuccess)
	defer stopGood()

	f := &Failover{servers: []string{badAddr, goodAddr}}
	req := new(dns.Msg)
	req.SetQuestion("useful-failover.example.", dns.TypeA)
	req.RecursionDesired = true
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})
	ch.Reset(writer, req)
	ch.Next(context.Background())

	if got := writer.Msg(); got == nil || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("failover response = %#v, want useful second-server answer", got)
	}
	if badCalls.Load() != 1 || goodCalls.Load() != 1 {
		t.Fatalf("server calls = bad:%d good:%d, want 1/1", badCalls.Load(), goodCalls.Load())
	}
}

func TestFailoverResolutionAttemptProvenanceMarksSelectedTerminalFailure(t *testing.T) {
	failureAddr, failureCalls, stopFailure := startFailoverRcodeServer(t, dns.RcodeServerFailure)
	defer stopFailure()
	blockedAddr, blockedCalls, stopBlocked := startFailoverRcodeServer(t, dns.RcodeSuccess)
	defer stopBlocked()

	req := new(dns.Msg)
	req.SetQuestion("attempt-provenance.example.", dns.TypeA)
	req.RecursionDesired = true
	ctx := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	exhaustFailoverAttemptTuple(t, ctx, req.Question[0], blockedAddr)

	f := &Failover{servers: []string{failureAddr, blockedAddr}}
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})
	ch.Reset(writer, req)
	ch.Next(ctx)

	resp := writer.Msg()
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("failover response = %#v, want terminal SERVFAIL", resp)
	}
	if failureCalls.Load() != 1 || blockedCalls.Load() != 0 {
		t.Fatalf("server calls = failure:%d blocked:%d, want 1/0",
			failureCalls.Load(), blockedCalls.Load())
	}

	provenance := middleware.RequestLocalFailureForResponse(ctx, resp)
	if !errors.Is(provenance, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("terminal provenance = %v, want ErrResolutionAttemptLimit", provenance)
	}
	var limitErr *middleware.ResolutionAttemptLimitError
	if !errors.As(provenance, &limitErr) {
		t.Fatalf("terminal provenance type = %T, want *ResolutionAttemptLimitError", provenance)
	}
	if got, want := limitErr.Endpoint, middleware.CanonicalResolutionEndpoint(blockedAddr); got != want {
		t.Fatalf("blocked endpoint = %q, want %q", got, want)
	}
	if copied := middleware.RequestLocalFailureForResponse(ctx, resp.Copy()); copied != nil {
		t.Fatalf("copied response inherited exact-response provenance: %v", copied)
	}
}

func TestFailoverResolutionAttemptProvenanceDoesNotMarkRecovery(t *testing.T) {
	blockedAddr, blockedCalls, stopBlocked := startFailoverRcodeServer(t, dns.RcodeServerFailure)
	defer stopBlocked()
	goodAddr, goodCalls, stopGood := startFailoverRcodeServer(t, dns.RcodeSuccess)
	defer stopGood()

	req := new(dns.Msg)
	req.SetQuestion("attempt-recovery.example.", dns.TypeA)
	req.RecursionDesired = true
	ctx := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	exhaustFailoverAttemptTuple(t, ctx, req.Question[0], blockedAddr)

	f := &Failover{servers: []string{blockedAddr, goodAddr}}
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})
	ch.Reset(writer, req)
	ch.Next(ctx)

	resp := writer.Msg()
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("failover response = %#v, want useful recovery answer", resp)
	}
	if blockedCalls.Load() != 0 || goodCalls.Load() != 1 {
		t.Fatalf("server calls = blocked:%d good:%d, want 0/1",
			blockedCalls.Load(), goodCalls.Load())
	}
	if provenance := middleware.RequestLocalFailureForResponse(ctx, resp); provenance != nil {
		t.Fatalf("successful recovery inherited attempt-limit provenance: %v", provenance)
	}
}

func TestFailoverIncomingRequestLocalProvenanceFollowsSelectedResponse(t *testing.T) {
	tests := []struct {
		name      string
		rcode     int
		wantLocal bool
	}{
		{
			name:      "terminal fallback failure inherits provenance",
			rcode:     dns.RcodeServerFailure,
			wantLocal: true,
		},
		{
			name:  "successful fallback drops losing provenance",
			rcode: dns.RcodeSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, calls, stop := startFailoverRcodeServer(t, tt.rcode)
			defer stop()

			ctx := middleware.WithResolutionAttemptGuard(
				context.Background(),
				middleware.NewResolutionAttemptGuard(),
			)
			req := new(dns.Msg)
			req.SetQuestion("incoming-local.example.", dns.TypeA)
			req.RecursionDesired = true
			incoming := new(dns.Msg)
			incoming.SetRcode(req, dns.RcodeServerFailure)
			middleware.MarkRequestLocalFailureResponse(ctx, incoming, context.DeadlineExceeded)

			writer := mock.NewWriter("udp", "127.0.0.1:0")
			responseWriter := &ResponseWriter{
				ResponseWriter: writer,
				f:              &Failover{servers: []string{addr}},
				ctx:            ctx,
				req:            middleware.NewRequest(req),
			}
			if err := responseWriter.WriteMsg(incoming); err != nil {
				t.Fatalf("WriteMsg: %v", err)
			}

			resp := writer.Msg()
			if resp == nil || resp.Rcode != tt.rcode {
				t.Fatalf("failover response = %#v, want rcode %s",
					resp, dns.RcodeToString[tt.rcode])
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("fallback calls = %d, want 1", got)
			}

			provenance := middleware.RequestLocalFailureForResponse(ctx, resp)
			if tt.wantLocal {
				if !errors.Is(provenance, context.DeadlineExceeded) {
					t.Fatalf("terminal provenance = %v, want context deadline", provenance)
				}
				if resp == incoming {
					t.Fatal("terminal provenance was not propagated to the selected fallback response")
				}
			} else if provenance != nil {
				t.Fatalf("successful fallback inherited request-local provenance: %v", provenance)
			}
		})
	}
}

func TestFailoverStopsWhenIngressContextIsDone(t *testing.T) {
	addr, calls, stop := startFailoverRcodeServer(t, dns.RcodeSuccess)
	defer stop()

	tests := []struct {
		name string
		ctx  func(context.Context) (context.Context, context.CancelFunc)
		err  error
	}{
		{
			name: "canceled",
			ctx: func(parent context.Context) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(parent)
				cancel()
				return ctx, func() {}
			},
			err: context.Canceled,
		},
		{
			name: "deadline",
			ctx: func(parent context.Context) (context.Context, context.CancelFunc) {
				return context.WithDeadline(parent, time.Now().Add(-time.Second))
			},
			err: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := middleware.WithResolutionAttemptGuard(
				context.Background(),
				middleware.NewResolutionAttemptGuard(),
			)
			ctx, cancel := tt.ctx(base)
			defer cancel()

			req := new(dns.Msg)
			req.SetQuestion("done-context.example.", dns.TypeA)
			req.RecursionDesired = true
			writer := mock.NewWriter("udp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{
				&Failover{servers: []string{addr}},
				&dummy{},
			})
			ch.Reset(writer, req)
			ch.Next(ctx)

			if got := calls.Load(); got != 0 {
				t.Fatalf("fallback calls = %d, want 0", got)
			}
			if resp := writer.Msg(); resp == nil || resp.Rcode != dns.RcodeServerFailure {
				t.Fatalf("response = %#v, want original SERVFAIL", resp)
			}
			if err := middleware.RequestLocalFailureForResponse(ctx, writer.Msg()); !errors.Is(err, tt.err) {
				t.Fatalf("response provenance = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestFailoverFailureProbeLimitIsTerminal(t *testing.T) {
	addr, calls, stop := startFailoverRcodeServer(t, dns.RcodeSuccess)
	defer stop()

	ctx := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	req := new(dns.Msg)
	req.SetQuestion("probe-limit.example.", dns.TypeA)
	req.RecursionDesired = true
	incoming := new(dns.Msg)
	incoming.SetRcode(req, dns.RcodeServerFailure)
	middleware.MarkRequestLocalFailureResponse(ctx, incoming, middleware.ErrFailureProbeLimit)

	writer := mock.NewWriter("udp", "127.0.0.1:0")
	responseWriter := &ResponseWriter{
		ResponseWriter: writer,
		f:              &Failover{servers: []string{addr}},
		ctx:            ctx,
		req:            middleware.NewRequest(req),
	}
	if err := responseWriter.WriteMsg(incoming); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}

	if got := calls.Load(); got != 0 {
		t.Fatalf("fallback calls = %d, want 0", got)
	}
	if writer.Msg() != incoming {
		t.Fatal("failure-probe limit response was replaced")
	}
}

func TestFailoverInFlightAttemptHonorsIngressDeadline(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		started <- struct{}{}
		<-release
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = w.WriteMsg(resp)
	})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Net: "udp", PacketConn: packet, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() {
		close(release)
		_ = srv.Shutdown()
	}()

	goodAddr, goodCalls, stopGood := startFailoverRcodeServer(t, dns.RcodeSuccess)
	defer stopGood()

	base := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	ctx, cancel := context.WithTimeout(base, 50*time.Millisecond)
	defer cancel()
	req := new(dns.Msg)
	req.SetQuestion("bounded-failover.example.", dns.TypeA)
	req.RecursionDesired = true
	incoming := new(dns.Msg)
	incoming.SetRcode(req, dns.RcodeServerFailure)
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	responseWriter := &ResponseWriter{
		ResponseWriter: writer,
		f: &Failover{servers: []string{
			packet.LocalAddr().String(),
			goodAddr,
		}},
		ctx: ctx,
		req: middleware.NewRequest(req),
	}

	start := time.Now()
	if err := responseWriter.WriteMsg(incoming); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("failover returned after %v, want ingress deadline bound", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("blocking fallback did not receive first attempt")
	}
	if got := goodCalls.Load(); got != 0 {
		t.Fatalf("second fallback calls = %d, want 0 after ingress deadline", got)
	}
	if err := middleware.RequestLocalFailureForResponse(ctx, writer.Msg()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("terminal provenance = %v, want DeadlineExceeded", err)
	}
}

func exhaustFailoverAttemptTuple(
	t *testing.T,
	ctx context.Context,
	question dns.Question,
	endpoint string,
) {
	t.Helper()

	for range 3 {
		if err := middleware.BeginResolutionAttempt(ctx, question, endpoint, "udp"); err != nil {
			t.Fatalf("pre-consuming attempt tuple: %v", err)
		}
	}
}

func TestFailoverNormalizesCheckingDisabled(t *testing.T) {
	tests := []struct {
		name  string
		rcode int
	}{
		{name: "useful response", rcode: dns.RcodeSuccess},
		{name: "failure response", rcode: dns.RcodeServerFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, stop := startFailoverCDServer(t, tt.rcode, false)
			defer stop()

			f := &Failover{servers: []string{addr}}
			req := new(dns.Msg)
			req.SetQuestion("cd-failover.example.", dns.TypeA)
			req.RecursionDesired = true
			req.CheckingDisabled = true
			writer := mock.NewWriter("udp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})
			ch.Reset(writer, req)
			ch.Next(context.Background())

			got := writer.Msg()
			if got == nil || got.Rcode != tt.rcode {
				t.Fatalf("failover response = %#v, want rcode %s", got, dns.RcodeToString[tt.rcode])
			}
			if !got.CheckingDisabled {
				t.Fatal("fallback response lost the client CD=1 bit")
			}
		})
	}
}

func TestNewDeduplicatesCanonicalFallbackEndpoints(t *testing.T) {
	cfg := new(config.Config)
	cfg.FallbackServers = []string{
		"192.0.2.1:53",
		"192.0.2.1:053",
		"[2001:db8::1]:53",
		"[2001:0DB8:0:0::1]:053",
	}

	f := New(cfg)
	if got := len(f.servers); got != 2 {
		t.Fatalf("canonical fallback servers = %d, want 2", got)
	}
}

func startFailoverRcodeServer(t *testing.T, rcode int) (string, *atomic.Int32, func()) {
	t.Helper()

	calls := new(atomic.Int32)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		calls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = rcode
		if rcode == dns.RcodeSuccess {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 43),
			}}
		}
		_ = w.WriteMsg(resp)
	})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Net: "udp", PacketConn: packet, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return packet.LocalAddr().String(), calls, func() { _ = srv.Shutdown() }
}

func startFailoverCDServer(t *testing.T, rcode int, cd bool) (string, func()) {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = rcode
		resp.CheckingDisabled = cd
		if rcode == dns.RcodeSuccess {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 44),
			}}
		}
		_ = w.WriteMsg(resp)
	})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Net: "udp", PacketConn: packet, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return packet.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func startFailoverServer(t *testing.T, mismatchQuestion bool) (
	addr string,
	calls *atomic.Int32,
	stop func(),
) {
	t.Helper()

	calls = new(atomic.Int32)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		calls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		if mismatchQuestion {
			resp.Question = []dns.Question{{
				Name:   "mismatch.example.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}}
		} else {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 20),
			}}
		}
		_ = w.WriteMsg(resp)
	})

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	server := &dns.Server{Net: "udp", PacketConn: packet, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()

	return packet.LocalAddr().String(), calls, func() { _ = server.Shutdown() }
}

// vacantLoopbackAddr returns the address of a server that answers with
// something that is not a DNS message, which is a deterministic failure.
// An address assumed closed is a race. It can be taken between being
// released and being used, and a silent one costs a full timeout.
func vacantLoopbackAddr(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			_, _ = pc.WriteTo([]byte("not a DNS message")[:min(n, 17)], from)
		}
	}()

	return pc.LocalAddr().String()
}
