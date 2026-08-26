package forwarder

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
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

func startTestDNSServer(t *testing.T, network string) (addr string, stop func()) {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if len(r.Question) > 0 && strings.EqualFold(r.Question[0].Name, "example.com.") && r.Question[0].Qtype == dns.TypeA {
			a, err := dns.NewRR("example.com. 60 IN A 93.184.216.34")
			if err == nil {
				m.Answer = []dns.RR{a}
			}
		}

		_ = w.WriteMsg(m)
	})

	s := &dns.Server{Net: network, Handler: mux}

	switch network {
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		s.PacketConn = pc
		addr = pc.LocalAddr().String()
		go func() { _ = s.ActivateAndServe() }()
		stop = func() { _ = s.Shutdown() }
		return addr, stop
	case "tcp-tls":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		addr = ln.Addr().String()

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			_ = ln.Close()
			t.Fatalf("generate key: %v", err)
		}

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "sdns-forwarder-test"},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
		if err != nil {
			_ = ln.Close()
			t.Fatalf("create cert: %v", err)
		}

		cert := tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: privKey}
		tlsLn := tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
		s.Listener = tlsLn
		go func() { _ = s.ActivateAndServe() }()
		stop = func() { _ = s.Shutdown() }
		return addr, stop
	default:
		t.Fatalf("unsupported network: %q", network)
		return "", func() {}
	}
}

func Test_Forwarder(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	udpAddr, stopUDP := startTestDNSServer(t, "udp")
	defer stopUDP()

	tlsAddr, stopTLS := startTestDNSServer(t, "tcp-tls")
	defer stopTLS()

	cfg := new(config.Config)
	// Keep a known-bad entry first to exercise failover, but use local servers
	// so the test is hermetic and does not require external DNS reachability.
	// The bad entry is a closed loopback port rather than a black-holed
	// address: both fail, but one fails now and the other only after a
	// timeout, and this test is about the failover, not the wait.
	cfg.ForwarderServers = []string{vacantLoopbackAddr(t), udpAddr, "1", "tls://" + tlsAddr}

	// The registry is process-wide, so a second run in the same process —
	// go test -count=2, say — would otherwise panic on re-registration.
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("forwarder", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	f := middleware.Get("forwarder").(*Forwarder)
	if !reflect.DeepEqual("forwarder", f.Name()) {
		t.Errorf("f.Name() = %v, want %v", f.Name(), "forwarder")
	}
	// Test TLS forwarding against a local server using a self-signed cert.
	// In production, users should provide a validating TLS configuration.
	f.tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only

	ch := middleware.NewChain([]middleware.Handler{f})

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	ch.Request = middleware.NewRequest(req)

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(dns.RcodeSuccess, ch.Writer.Rcode()) {
		t.Errorf("ch.Writer.Rcode() = %v, want %v", ch.Writer.Rcode(), dns.RcodeSuccess)
	}

	req.RecursionDesired = true

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(dns.RcodeSuccess, ch.Writer.Rcode()) {
		t.Errorf("ch.Writer.Rcode() = %v, want %v", ch.Writer.Rcode(), dns.RcodeSuccess)
	}

	f.servers = []*server{}

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(dns.RcodeServerFailure, ch.Writer.Rcode()) {
		t.Errorf("ch.Writer.Rcode() = %v, want %v", ch.Writer.Rcode(), dns.RcodeServerFailure)
	}

	srv := &server{Addr: vacantLoopbackAddr(t), Proto: "udp"}
	f.servers = []*server{srv}

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(dns.RcodeServerFailure, ch.Writer.Rcode()) {
		t.Errorf("ch.Writer.Rcode() = %v, want %v", ch.Writer.Rcode(), dns.RcodeServerFailure)
	}

	srv = &server{Addr: tlsAddr, Proto: "tcp-tls"}
	f.servers = []*server{srv}

	ch.Reset(mw, req)
	ch.Next(ctx)

	if !reflect.DeepEqual(dns.RcodeSuccess, ch.Writer.Rcode()) {
		t.Errorf("ch.Writer.Rcode() = %v, want %v", ch.Writer.Rcode(), dns.RcodeSuccess)
	}
}

// startMismatchedQuestionServer returns a UDP server that always replies with
// a fixed question section (victim.test. A) regardless of the client's query.
// It models a malicious or misbehaving upstream attempting cache poisoning.
func startMismatchedQuestionServer(t *testing.T) (addr string, stop func()) {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Question = []dns.Question{{Name: "victim.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		if rr, err := dns.NewRR("victim.test. 60 IN A 6.6.6.6"); err == nil {
			m.Answer = []dns.RR{rr}
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &dns.Server{Net: "udp", Handler: mux, PacketConn: pc}
	go func() { _ = s.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = s.Shutdown() }
}

func Test_Forwarder_RejectsMismatchedQuestion(t *testing.T) {
	addr, stop := startMismatchedQuestionServer(t)
	defer stop()

	f := &Forwarder{servers: []*server{{Addr: addr, Proto: "udp"}}}

	ch := middleware.NewChain([]middleware.Handler{f})
	mw := mock.NewWriter("udp", "127.0.0.1:0")

	req := new(dns.Msg)
	req.SetQuestion("attacker.test.", dns.TypeA)

	ch.Reset(mw, req)
	ch.Next(context.Background())

	// Every upstream returns a mismatched question, so the forwarder must
	// drop the response and report SERVFAIL rather than letting an unrelated
	// answer through to the client (and the cache).
	if !reflect.DeepEqual(dns.RcodeServerFailure, ch.Writer.Rcode()) {
		t.Errorf("ch.Writer.Rcode() = %v, want %v", ch.Writer.Rcode(), dns.RcodeServerFailure)
	}
}

func TestForwarderResolutionAttemptGuardBoundsDuplicateEndpoints(t *testing.T) {
	addr, stop := startMismatchedQuestionServer(t)
	defer stop()

	duplicate := &server{Addr: addr, Proto: "udp"}
	f := &Forwarder{servers: []*server{duplicate, duplicate, duplicate, duplicate, duplicate}}
	ch := middleware.NewChain([]middleware.Handler{f})
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("attempt-guard.example.", dns.TypeA)
	ch.Reset(mw, req)

	before := forwarderResponseMismatch.Value()
	ch.Next(context.Background())

	if got := forwarderResponseMismatch.Value() - before; got != 3 {
		t.Fatalf("wire mismatches = %d, want exactly 3 attempts", got)
	}
	if mw.Rcode() != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[mw.Rcode()])
	}
}

func TestForwarderTriesNextServerAfterUnusableDNSResponse(t *testing.T) {
	badAddr, badCalls, stopBad := startForwarderRcodeServer(t, dns.RcodeServerFailure)
	defer stopBad()
	goodAddr, goodCalls, stopGood := startForwarderRcodeServer(t, dns.RcodeSuccess)
	defer stopGood()

	f := &Forwarder{servers: []*server{
		{Addr: badAddr, Proto: "udp"},
		{Addr: goodAddr, Proto: "udp"},
	}}
	ch := middleware.NewChain([]middleware.Handler{f})
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("useful-response.example.", dns.TypeA)
	ch.Reset(writer, req)
	ch.Next(context.Background())

	if got := writer.Msg(); got == nil || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("forwarder response = %#v, want useful second-server answer", got)
	}
	if badCalls.Load() != 1 || goodCalls.Load() != 1 {
		t.Fatalf("server calls = bad:%d good:%d, want 1/1", badCalls.Load(), goodCalls.Load())
	}
}

func TestForwarderResolutionAttemptProvenanceMarksSelectedTerminalFailure(t *testing.T) {
	failureAddr, failureCalls, stopFailure := startForwarderRcodeServer(t, dns.RcodeServerFailure)
	defer stopFailure()
	blockedAddr, blockedCalls, stopBlocked := startForwarderRcodeServer(t, dns.RcodeSuccess)
	defer stopBlocked()

	req := new(dns.Msg)
	req.SetQuestion("attempt-provenance.example.", dns.TypeA)
	ctx := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	exhaustForwarderAttemptTuple(t, ctx, req.Question[0], blockedAddr)

	f := &Forwarder{servers: []*server{
		{Addr: failureAddr, Proto: "udp"},
		{Addr: blockedAddr, Proto: "udp"},
	}}
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f})
	ch.Reset(writer, req)
	ch.Next(ctx)

	resp := writer.Msg()
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("forwarder response = %#v, want terminal SERVFAIL", resp)
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

func TestForwarderResolutionAttemptProvenanceDoesNotMarkRecovery(t *testing.T) {
	blockedAddr, blockedCalls, stopBlocked := startForwarderRcodeServer(t, dns.RcodeServerFailure)
	defer stopBlocked()
	goodAddr, goodCalls, stopGood := startForwarderRcodeServer(t, dns.RcodeSuccess)
	defer stopGood()

	req := new(dns.Msg)
	req.SetQuestion("attempt-recovery.example.", dns.TypeA)
	ctx := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	exhaustForwarderAttemptTuple(t, ctx, req.Question[0], blockedAddr)

	f := &Forwarder{servers: []*server{
		{Addr: blockedAddr, Proto: "udp"},
		{Addr: goodAddr, Proto: "udp"},
	}}
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f})
	ch.Reset(writer, req)
	ch.Next(ctx)

	resp := writer.Msg()
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("forwarder response = %#v, want useful recovery answer", resp)
	}
	if blockedCalls.Load() != 0 || goodCalls.Load() != 1 {
		t.Fatalf("server calls = blocked:%d good:%d, want 0/1",
			blockedCalls.Load(), goodCalls.Load())
	}
	if provenance := middleware.RequestLocalFailureForResponse(ctx, resp); provenance != nil {
		t.Fatalf("successful recovery inherited attempt-limit provenance: %v", provenance)
	}
}

func TestForwarderResolutionAttemptProvenanceMarksAllTuplesBlocked(t *testing.T) {
	blockedAddr, blockedCalls, stopBlocked := startForwarderRcodeServer(t, dns.RcodeSuccess)
	defer stopBlocked()

	req := new(dns.Msg)
	req.SetQuestion("all-tuples-blocked.example.", dns.TypeA)
	ctx := middleware.WithResolutionAttemptGuard(
		context.Background(),
		middleware.NewResolutionAttemptGuard(),
	)
	exhaustForwarderAttemptTuple(t, ctx, req.Question[0], blockedAddr)

	f := &Forwarder{servers: []*server{{Addr: blockedAddr, Proto: "udp"}}}
	writer := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f})
	ch.Reset(writer, req)
	ch.Next(ctx)

	resp := writer.Msg()
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("forwarder response = %#v, want terminal SERVFAIL", resp)
	}
	if got := blockedCalls.Load(); got != 0 {
		t.Fatalf("blocked tuple reached wire %d times, want 0", got)
	}
	provenance := middleware.RequestLocalFailureForResponse(ctx, resp)
	if !errors.Is(provenance, middleware.ErrResolutionAttemptLimit) {
		t.Fatalf("all-tuples-blocked provenance = %v, want ErrResolutionAttemptLimit", provenance)
	}
	var limitErr *middleware.ResolutionAttemptLimitError
	if !errors.As(provenance, &limitErr) {
		t.Fatalf("all-tuples-blocked provenance type = %T, want *ResolutionAttemptLimitError", provenance)
	}
}

type contextWaitRoundTripper struct {
	calls atomic.Int32
}

func (rt *contextWaitRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestForwarderTimeoutProvenanceUsesOverallContextOnly(t *testing.T) {
	tests := []struct {
		name          string
		queryTimeout  time.Duration
		clientTimeout time.Duration
		wantLocal     bool
	}{
		{
			name:         "derived query timeout is request local",
			queryTimeout: 20 * time.Millisecond,
			wantLocal:    true,
		},
		{
			name:          "endpoint timeout remains shareable",
			queryTimeout:  time.Second,
			clientTimeout: 20 * time.Millisecond,
			wantLocal:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := new(contextWaitRoundTripper)
			endpoint := "https://timeout.example/dns-query"
			f := &Forwarder{
				servers: []*server{{
					Addr:      endpoint,
					Proto:     "doh",
					DoHURL:    endpoint,
					DoHClient: &http.Client{Transport: transport, Timeout: tt.clientTimeout},
				}},
				queryTimeout: tt.queryTimeout,
			}

			ctx := middleware.WithResolutionAttemptGuard(
				context.Background(),
				middleware.NewResolutionAttemptGuard(),
			)
			req := new(dns.Msg)
			req.SetQuestion("timeout-provenance.example.", dns.TypeA)
			req.SetEdns0(dnsutil.DefaultMsgSize, true)
			writer := mock.NewWriter("udp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{f})
			ch.Reset(writer, req)
			ch.Next(ctx)

			resp := writer.Msg()
			if resp == nil || resp.Rcode != dns.RcodeServerFailure {
				t.Fatalf("forwarder response = %#v, want terminal SERVFAIL", resp)
			}
			if ede := dnsutil.GetEDE(resp); ede != nil {
				t.Fatalf("forwarder timeout changed historical plain SERVFAIL into EDE: %+v", ede)
			}
			if got := transport.calls.Load(); got != 1 {
				t.Fatalf("transport calls = %d, want 1", got)
			}

			provenance := middleware.RequestLocalFailureForResponse(ctx, resp)
			if tt.wantLocal {
				if !errors.Is(provenance, context.DeadlineExceeded) {
					t.Fatalf("overall-timeout provenance = %v, want context deadline", provenance)
				}
				if copied := middleware.RequestLocalFailureForResponse(ctx, resp.Copy()); copied != nil {
					t.Fatalf("copied timeout response inherited provenance: %v", copied)
				}
			} else if provenance != nil {
				t.Fatalf("endpoint timeout was misclassified as request local: %v", provenance)
			}
		})
	}
}

func exhaustForwarderAttemptTuple(
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

func TestNewDeduplicatesCanonicalForwarderEndpointsPerTransport(t *testing.T) {
	cfg := new(config.Config)
	cfg.ForwarderServers = []string{
		"192.0.2.1:53",
		"192.0.2.1:053",
		"tls://192.0.2.1:53",
		"tls://192.0.2.1:053",
		"https://192.0.2.1/dns-query",
		"https://192.0.2.1:443/dns-query",
	}

	f := New(cfg)
	if got := len(f.servers); got != 3 {
		t.Fatalf("canonical servers = %d, want one per transport", got)
	}
}

func startForwarderRcodeServer(t *testing.T, rcode int) (string, *atomic.Int32, func()) {
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
				A: net.IPv4(192, 0, 2, 42),
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

func TestForwarderRecursionWorkCountsUDPToTCPAttempts(t *testing.T) {
	tests := []struct {
		name         string
		mode         middleware.RecursionWorkMode
		wantRcode    int
		wantTCP      int32
		wantOutbound uint32
		wantEDE      bool
	}{
		{
			name:         "enforce rejects TCP fallback at cap",
			mode:         middleware.RecursionWorkEnforce,
			wantRcode:    dns.RcodeServerFailure,
			wantTCP:      0,
			wantOutbound: 1,
			wantEDE:      true,
		},
		{
			name:         "shadow observes but preserves fallback",
			mode:         middleware.RecursionWorkShadow,
			wantRcode:    dns.RcodeSuccess,
			wantTCP:      1,
			wantOutbound: 2,
			wantEDE:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, udpCalls, tcpCalls, stop := startTruncatingForwarderServers(t)
			defer stop()

			f := &Forwarder{
				servers:     []*server{{Addr: addr, Proto: "udp"}},
				dialTimeout: time.Second,
			}
			ledger := middleware.NewRecursionWorkLedger(middleware.RecursionWorkPolicy{
				Mode:               tt.mode,
				MaxOutboundQueries: 1,
				MaxInternalQueries: 32,
			})
			ctx := middleware.WithRecursionWork(context.Background(), ledger)

			req := new(dns.Msg)
			req.SetQuestion("fallback.example.", dns.TypeA)
			req.SetEdns0(1232, true)
			req.RecursionDesired = true
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			ch := middleware.NewChain([]middleware.Handler{f})
			ch.Reset(mw, req)
			ch.Next(ctx)

			resp := mw.Msg()
			if resp == nil || resp.Rcode != tt.wantRcode {
				t.Fatalf("response = %#v, want rcode %s", resp, dns.RcodeToString[tt.wantRcode])
			}
			if got := udpCalls.Load(); got != 1 {
				t.Fatalf("UDP calls = %d, want 1", got)
			}
			if got := tcpCalls.Load(); got != tt.wantTCP {
				t.Fatalf("TCP calls = %d, want %d", got, tt.wantTCP)
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

func startTruncatingForwarderServers(t *testing.T) (
	addr string,
	udpCalls, tcpCalls *atomic.Int32,
	stop func(),
) {
	t.Helper()

	udpCalls = new(atomic.Int32)
	tcpCalls = new(atomic.Int32)

	udpMux := dns.NewServeMux()
	udpMux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		udpCalls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Truncated = true
		_ = w.WriteMsg(resp)
	})
	// The forwarder retries TCP against the same server address, so both
	// listeners must hold the same port. Only one of the two draws it from
	// :0, and it is the TCP one on purpose: a port the kernel hands out for
	// TCP is one TCP can bind, whereas a port drawn for UDP carries no such
	// promise for TCP — on Windows it can sit inside a range excluded for
	// the other protocol, where the bind fails with a permission error.
	// Drawing on the constrained side turns the likely failure into the
	// unlikely one; the redraw covers what is left.
	var (
		packet   net.PacketConn
		listener net.Listener
	)
	for attempt := 1; ; attempt++ {
		var err error
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen TCP: %v", err)
		}
		host, port, err := net.SplitHostPort(listener.Addr().String())
		if err != nil {
			_ = listener.Close()
			t.Fatalf("split TCP address: %v", err)
		}
		packet, err = net.ListenPacket("udp", net.JoinHostPort(host, port))
		if err == nil {
			break
		}
		_ = listener.Close()
		if attempt == 10 {
			t.Fatalf("listen UDP on TCP port after %d attempts: %v", attempt, err)
		}
	}
	udpServer := &dns.Server{Net: "udp", PacketConn: packet, Handler: udpMux}
	go func() { _ = udpServer.ActivateAndServe() }()
	tcpMux := dns.NewServeMux()
	tcpMux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		tcpCalls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(192, 0, 2, 10),
		}}
		_ = w.WriteMsg(resp)
	})
	tcpServer := &dns.Server{Net: "tcp", Listener: listener, Handler: tcpMux}
	go func() { _ = tcpServer.ActivateAndServe() }()

	return packet.LocalAddr().String(), udpCalls, tcpCalls, func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	}
}

// vacantLoopbackAddr returns the address of a server that answers with
// something that is not a DNS message, which is a deterministic failure.
// An address assumed closed is a race — it can be taken between being
// released and being used — and a silent one costs a full timeout.
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

func TestServersForPicksTheZoneUpstreams(t *testing.T) {
	f := New(&config.Config{
		ForwarderServers: []string{"192.0.2.1:53"},
		ForwardZones: []config.ForwardZoneConfig{
			{Name: "corp.example.", Servers: []string{"10.0.0.53:53"}},
			{Name: "lab.corp.example.", Servers: []string{"tls://10.0.1.53:853"}},
			{Name: "broken.example.", Servers: []string{"not-an-address"}},
		},
	})

	addrOf := func(servers []*server) string {
		if len(servers) != 1 {
			t.Fatalf("expected exactly one upstream, got %d", len(servers))
		}
		return servers[0].Addr
	}

	if got := addrOf(f.serversFor("host.corp.example.")); got != "10.0.0.53:53" {
		t.Fatalf("corp zone upstream = %s", got)
	}
	if got := addrOf(f.serversFor("host.lab.corp.example.")); got != "10.0.1.53:853" {
		t.Fatalf("most specific zone upstream = %s", got)
	}
	if got := addrOf(f.serversFor("example.net.")); got != "192.0.2.1:53" {
		t.Fatalf("unmatched name upstream = %s, want the whole-server list", got)
	}
	// A zone whose servers were all unusable must not borrow the public
	// whole-server list: that would send an internal zone's questions
	// exactly where configuring the zone was meant to stop them going.
	if servers := f.serversFor("host.broken.example."); len(servers) != 0 {
		t.Fatalf("unusable zone fell back to %v, want no upstream at all", servers)
	}
}

func TestServersForWithoutZonesIsTheGlobalList(t *testing.T) {
	f := New(&config.Config{ForwarderServers: []string{"192.0.2.1:53"}})
	if len(f.zones) != 0 {
		t.Fatalf("zones = %v, want none", f.zones)
	}
	if servers := f.serversFor("anything.example."); len(servers) != 1 || servers[0].Addr != "192.0.2.1:53" {
		t.Fatalf("serversFor = %v, want the whole-server list", servers)
	}
}
