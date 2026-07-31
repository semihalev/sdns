package dnsclient

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
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startServer launches a local DNS server on the given network ("udp"
// or "tcp") driven by handler, returning its address and a stop func.
func startServer(t *testing.T, network string, handler dns.HandlerFunc) (addr string, stop func()) {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)
	s := &dns.Server{Net: network, Handler: mux}

	switch network {
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		s.PacketConn = pc
		addr = pc.LocalAddr().String()
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		s.Listener = ln
		addr = ln.Addr().String()
	default:
		t.Fatalf("unsupported network %q", network)
	}

	go func() { _ = s.ActivateAndServe() }()
	return addr, func() { _ = s.Shutdown() }
}

// startDoTServer launches a DNS-over-TLS server with a self-signed cert
// and returns its address plus a *tls.Config that trusts the cert.
func startDoTServer(t *testing.T, handler dns.HandlerFunc) (addr string, cfg *tls.Config, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr = ln.Addr().String()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sdns-dnsclient-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)
	// Hand the server a TLS-wrapped listener: miekg uses a provided
	// Listener as-is, so it must already terminate TLS.
	s := &dns.Server{Net: "tcp-tls", Listener: tls.NewListener(ln, serverCfg), Handler: mux}
	go func() { _ = s.ActivateAndServe() }()
	return addr, &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS12}, func() { _ = s.Shutdown() }
}

// answerExample replies to example.com. A with a fixed address and
// echoes every other query as an empty NOERROR.
func answerExample(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
		if rr, err := dns.NewRR(r.Question[0].Name + " 60 IN A 93.184.216.34"); err == nil {
			m.Answer = []dns.RR{rr}
		}
	}
	_ = w.WriteMsg(m)
}

func newReq() *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	return req
}

func TestClientExchange_UDP(t *testing.T) {
	addr, stop := startServer(t, "udp", answerExample)
	defer stop()

	c := &Client{Proto: "udp", Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(context.Background(), newReq(), addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
}

func TestClientExchange_TCP(t *testing.T) {
	addr, stop := startServer(t, "tcp", answerExample)
	defer stop()

	c := &Client{Proto: "tcp", Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(context.Background(), newReq(), addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
}

func TestClientExchange_DoT(t *testing.T) {
	addr, cfg, stop := startDoTServer(t, answerExample)
	defer stop()

	c := &Client{Proto: "tcp-tls", Timeout: 5 * time.Second, TLSConfig: cfg}
	resp, _, err := c.Exchange(context.Background(), newReq(), addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
}

// On UDP a wrong-ID reply is treated as a stray packet and skipped (it
// might be a late reply to a timed-out query, or a spoof). With no
// matching response, the exchange times out rather than accepting the
// wrong answer or failing fast — matching miekg/dns.Client.
func TestClientExchange_IDMismatch_UDPSkipsAndTimesOut(t *testing.T) {
	addr, stop := startServer(t, "udp", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Id = r.Id + 1 // wrong transaction ID
		_ = w.WriteMsg(m)
	})
	defer stop()

	c := &Client{Proto: "udp", Timeout: 300 * time.Millisecond}
	resp, _, err := c.Exchange(context.Background(), newReq(), addr)
	if err == nil {
		t.Fatalf("expected a timeout, got resp %v", resp)
	}
	if errors.Is(err, dns.ErrId) {
		t.Fatal("UDP must skip mismatched IDs, not fail fast with ErrId")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected a timeout error after skipping the stray packet, got %v", err)
	}
}

// On a TCP stream there is a single in-flight response, so a mismatched
// ID is a genuine protocol error and must fail fast with ErrId.
func TestClientExchange_IDMismatch_TCP(t *testing.T) {
	addr, stop := startServer(t, "tcp", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Id = r.Id + 1 // wrong transaction ID
		_ = w.WriteMsg(m)
	})
	defer stop()

	c := &Client{Proto: "tcp", Timeout: 2 * time.Second}
	_, _, err := c.Exchange(context.Background(), newReq(), addr)
	if !errors.Is(err, dns.ErrId) {
		t.Fatalf("expected ErrId on TCP, got %v", err)
	}
}

func TestClientExchange_QuestionMismatch(t *testing.T) {
	addr, stop := startServer(t, "udp", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Question = []dns.Question{{Name: "victim.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		_ = w.WriteMsg(m)
	})
	defer stop()

	c := &Client{Proto: "udp", Timeout: 2 * time.Second}
	_, _, err := c.Exchange(context.Background(), newReq(), addr)
	if !errors.Is(err, ErrQuestion) {
		t.Fatalf("expected ErrQuestion, got %v", err)
	}
}

func TestClientExchange_TruncationFallsBackToTCP(t *testing.T) {
	// UDP server sets TC; TCP server returns the full answer. A correct
	// client must retry over TCP and surface the TCP answer.
	udpAddr, stopUDP := startServer(t, "udp", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	defer stopUDP()

	// The TCP listener must share the UDP address so the fallback dials
	// the same host:port. Bind TCP to the UDP port explicitly.
	host, port, _ := net.SplitHostPort(udpAddr)
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("listen tcp on %s: %v", udpAddr, err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", answerExample)
	s := &dns.Server{Net: "tcp", Listener: ln, Handler: mux}
	go func() { _ = s.ActivateAndServe() }()
	defer func() { _ = s.Shutdown() }()

	var attempts []string
	c := &Client{
		Proto:   "udp",
		Timeout: 2 * time.Second,
		BeforeAttempt: func(proto string) error {
			attempts = append(attempts, proto)
			return nil
		},
	}
	resp, _, err := c.Exchange(context.Background(), newReq(), udpAddr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Truncated {
		t.Fatal("expected the TCP (non-truncated) answer after fallback")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer from TCP fallback, got %d", len(resp.Answer))
	}
	if len(attempts) != 2 || attempts[0] != "udp" || attempts[1] != "tcp" {
		t.Fatalf("attempt protocols = %v, want [udp tcp]", attempts)
	}
}

func TestClientExchange_BeforeAttemptCanRejectTCPFallback(t *testing.T) {
	udpAddr, stopUDP := startServer(t, "udp", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	defer stopUDP()

	errBudget := errors.New("test attempt budget exhausted")
	var attempts []string
	c := &Client{
		Proto:   "udp",
		Timeout: 2 * time.Second,
		BeforeAttempt: func(proto string) error {
			attempts = append(attempts, proto)
			if proto == "tcp" {
				return errBudget
			}
			return nil
		},
	}

	resp, _, err := c.Exchange(context.Background(), newReq(), udpAddr)
	if !errors.Is(err, errBudget) {
		t.Fatalf("exchange error = %v, want %v", err, errBudget)
	}
	if resp != nil {
		t.Fatalf("response = %v, want nil after rejected TCP fallback", resp)
	}
	if len(attempts) != 2 || attempts[0] != "udp" || attempts[1] != "tcp" {
		t.Fatalf("attempt protocols = %v, want [udp tcp]", attempts)
	}
}

func TestClientExchange_CanceledContextSkipsAttemptHook(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var attempts int
	c := &Client{
		BeforeAttempt: func(string) error {
			attempts++
			return nil
		},
	}
	resp, _, err := c.Exchange(ctx, newReq(), "127.0.0.1:1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("exchange error = %v, want context.Canceled", err)
	}
	if resp != nil {
		t.Fatalf("response = %v, want nil", resp)
	}
	if attempts != 0 {
		t.Fatalf("attempt hook calls = %d, want 0 for canceled context", attempts)
	}
}

func TestClientExchange_CancelInterruptsInFlightUDPRead(t *testing.T) {
	received := make(chan struct{})
	release := make(chan struct{})
	addr, stop := startServer(t, "udp", func(dns.ResponseWriter, *dns.Msg) {
		close(received)
		<-release
	})
	defer func() {
		close(release)
		stop()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, err := (&Client{Proto: "udp"}).Exchange(ctx, newReq(), addr)
		result <- err
	}()

	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("server did not receive the in-flight UDP query")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exchange error = %v, want context.Canceled", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("in-flight UDP read ignored context cancellation")
	}
}

type blockingDeadlineConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
}

func (c *blockingDeadlineConn) SetDeadline(time.Time) error {
	close(c.started)
	<-c.release
	return nil
}

func TestInterruptOnCancelWaitsForStartedCallback(t *testing.T) {
	conn := &blockingDeadlineConn{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cleanup := InterruptOnCancel(ctx, conn)
	cancel()

	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback did not start")
	}
	cleanupDone := make(chan struct{})
	go func() {
		cleanup()
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
		t.Fatal("cleanup returned while SetDeadline callback was still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(conn.release)
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not return after cancellation callback completed")
	}

	secondCleanupDone := make(chan struct{})
	go func() {
		cleanup()
		close(secondCleanupDone)
	}()
	select {
	case <-secondCleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup was not idempotent")
	}
}

func TestInterruptOnCancelCleanupIsIdempotentAfterStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := InterruptOnCancel(ctx, nil)
	cleanup()

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("second cleanup blocked after the callback was stopped")
	}
}

func TestClientExchange_NilAttemptHookPreservesOperationError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A nil hook is the firewall-off path. Preserve the historical order in
	// which the transport starts its own operation instead of adding a new
	// eager context preflight. This malformed name makes DoH fail while
	// packing, before it needs an endpoint or HTTP client.
	req := new(dns.Msg)
	req.Question = []dns.Question{{
		Name:   strings.Repeat("a", 64) + ".",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	c := &Client{Proto: "doh"}
	resp, _, err := c.Exchange(ctx, req, "")
	if err == nil || !strings.Contains(err.Error(), "pack") {
		t.Fatalf("exchange error = %v, want DNS packing error", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("exchange error = %v, want operation error before context cancellation", err)
	}
	if resp != nil {
		t.Fatalf("response = %v, want nil", resp)
	}
}

func TestClientExchange_Timeout(t *testing.T) {
	// Server that never replies.
	addr, stop := startServer(t, "udp", func(w dns.ResponseWriter, r *dns.Msg) {})
	defer stop()

	c := &Client{Proto: "udp", Timeout: 200 * time.Millisecond}
	_, _, err := c.Exchange(context.Background(), newReq(), addr)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}

func BenchmarkClientExchangeUDP(b *testing.B) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", answerExample)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen udp: %v", err)
	}
	s := &dns.Server{Net: "udp", PacketConn: pc, Handler: mux}
	go func() { _ = s.ActivateAndServe() }()
	defer func() { _ = s.Shutdown() }()
	addr := pc.LocalAddr().String()

	c := &Client{Proto: "udp", Timeout: 2 * time.Second}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.Exchange(ctx, newReq(), addr); err != nil {
			b.Fatalf("exchange: %v", err)
		}
	}
}
