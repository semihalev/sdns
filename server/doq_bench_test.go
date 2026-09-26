package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/defaults"
	"github.com/semihalev/zlog/v2"
)

// doqBenchServer runs the default hit-path chain, the resolver replaced
// by the answer stub, behind a real DoQ listener on loopback, and returns
// a client connection to it.
func doqBenchServer(tb testing.TB) *quic.Conn {
	tb.Helper()
	dir := tb.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeBenchCert(tb, certPath, keyPath)

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	_ = probe.Close()

	// Setup and the listeners log; the benchmark's own lines must stay
	// readable to benchstat.
	logger := zlog.NewStructured()
	logger.SetWriter(io.Discard)
	zlog.SetDefault(logger)

	middleware.Reset()
	tb.Cleanup(middleware.Reset)
	defaults.RegisterUpTo("resolver")
	middleware.Register("bench-answer-stub", func(*config.Config) middleware.Handler { return benchAnswerStub{} })
	cfg := &config.Config{ //nolint:gosec // G101, the cookie secret is a test fixture, not a credential
		Bind:           "127.0.0.1:0",
		BindDOQ:        addr,
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
		Expire:         600,
		CacheSize:      10240,
		CookieSecret:   "6c6f6f6b61686172646c6f6f6b6168617264",
	}
	cfg.QueryTimeout.Duration = 10 * time.Second
	middleware.Setup(cfg)
	srv := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Run(ctx); err != nil {
		cancel()
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		cancel()
		for deadline := time.Now().Add(5 * time.Second); !srv.Stopped() && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		srv.Stop()
	})
	for deadline := time.Now().Add(3 * time.Second); !srv.HasListener("doq"); {
		if time.Now().After(deadline) {
			tb.Skip("doq listener did not come up")
		}
		time.Sleep(time.Millisecond)
	}

	conn, err := quic.DialAddr(context.Background(), addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, //nolint:gosec // loopback test server
		&quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: time.Second})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

func writeBenchCert(tb testing.TB, certPath, keyPath string) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doq.bench"},
		DNSNames:     []string{"doq.bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		tb.Fatal(err)
	}
}

// doqQuery sends one framed query on a fresh stream and reads the framed
// answer, as RFC 9250 asks: message ID 0, FIN after the query.
func doqQuery(conn *quic.Conn, query []byte, buf []byte) (int, error) {
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return 0, err
	}
	if _, err := stream.Write(query); err != nil {
		return 0, err
	}
	_ = stream.Close()
	var prefix [2]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(stream, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func doqFramedQuery(tb testing.TB, name string) []byte {
	tb.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.SetEdns0(1232, false)
	m.Id = 0
	raw, err := m.Pack()
	if err != nil {
		tb.Fatal(err)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(raw))), raw...) //nolint:gosec // a query is small
}

// BenchmarkDoQWarmHit is one cached answer per stream over one connection,
// client and server in one process: its allocations are both sides', and
// only the server side changes between the builds compared.
func BenchmarkDoQWarmHit(b *testing.B) {
	conn := doqBenchServer(b)
	query := doqFramedQuery(b, "warm.doq.test.")
	buf := make([]byte, 65535)
	if _, err := doqQuery(conn, query, buf); err != nil { // warm the cache
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		n, err := doqQuery(conn, query, buf)
		if err != nil || n < 12 {
			b.Fatalf("query: %d bytes, %v", n, err)
		}
	}
}

// BenchmarkDoQWarmHitParallel is the same with concurrent streams on the
// one connection, the shape DoQ exists for.
func BenchmarkDoQWarmHitParallel(b *testing.B) {
	conn := doqBenchServer(b)
	query := doqFramedQuery(b, "warm.doq.test.")
	if _, err := doqQuery(conn, query, make([]byte, 65535)); err != nil {
		b.Fatal(err)
	}
	b.SetParallelism(4)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 65535)
		for pb.Next() {
			if n, err := doqQuery(conn, query, buf); err != nil || n < 12 {
				b.Errorf("query: %d bytes, %v", n, err)
				return
			}
		}
	})
}
