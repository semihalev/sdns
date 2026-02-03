package forwarder

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/zlog/v2"
	"github.com/stretchr/testify/assert"
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
	cfg.ForwarderServers = []string{"[::255]:53", udpAddr, "1", "tls://" + tlsAddr}

	middleware.Register("forwarder", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	f := middleware.Get("forwarder").(*Forwarder)
	assert.Equal(t, "forwarder", f.Name())
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
	ch.Request = req

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	req.RecursionDesired = true

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	f.servers = []*server{}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeServerFailure, ch.Writer.Rcode())

	srv := &server{Addr: "[::255]:53", Proto: "udp"}
	f.servers = []*server{srv}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeServerFailure, ch.Writer.Rcode())

	srv = &server{Addr: tlsAddr, Proto: "tcp-tls"}
	f.servers = []*server{srv}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())
}
