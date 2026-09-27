package server

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/edns"
)

// A client that pads its query over DoT gets a reply padded to a multiple
// of 468 bytes (RFC 7830, RFC 8467 §4.1), from the resolution, which the
// Msg path writes, and from the cache, which the byte path writes. Over
// plain TCP the same query gets no padding, and a DoT client that did not
// pad gets none either.
func TestDoTRepliesArePaddedWhenTheClientPads(t *testing.T) {
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return edns.New(cfg) })
	middleware.Register("cache", func(cfg *config.Config) middleware.Handler { return cache.New(cfg) })
	middleware.Register("direct-pack-stub", func(*config.Config) middleware.Handler {
		return directPackStub{}
	})

	dir := t.TempDir()
	cert, key := generateTestCert(t, "dot.test")
	certPath, keyPath := dir+"/cert.pem", dir+"/key.pem"
	writeCertAndKey(t, certPath, keyPath, cert, key)
	cfg := &config.Config{
		Bind: "127.0.0.1:0", BindTLS: "127.0.0.1:0",
		TLSCertificate: certPath, TLSPrivateKey: keyPath,
		CacheSize: 1024, Expire: 600,
	}
	middleware.Setup(cfg)
	s := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tcp *tcpListener
	var dot *tlsListener
	for _, l := range s.listeners {
		switch l := l.(type) {
		case *tcpListener:
			tcp = l
		case *tlsListener:
			dot = l
		}
	}
	if tcp == nil || dot == nil {
		t.Fatal("fixture: no TCP or DoT listener")
	}
	for _, l := range []Listener{tcp, dot} {
		if err := l.Bind(ctx); err != nil {
			t.Fatal(err)
		}
		go func() { _ = l.Serve(ctx) }()
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), time.Second)
		defer scancel()
		_ = tcp.Shutdown(sctx)
		_ = dot.Shutdown(sctx)
	})
	tcp.mu.Lock()
	tcpAddr := tcp.ln.Addr().String()
	tcp.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for !dot.Serving() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	dotAddr := dot.ln.Addr().String()

	ask := func(t *testing.T, net, addr string, pad bool) (*dns.Msg, int) {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion("e2e.example.", dns.TypeA)
		req.SetEdns0(1232, false)
		if pad {
			opt := req.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 64)})
		}
		client := &dns.Client{Net: net, Timeout: 3 * time.Second,
			TLSConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // self-signed test cert
		conn, err := client.Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.WriteMsg(req); err != nil {
			t.Fatal(err)
		}
		raw, err := conn.ReadMsgHeader(nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(raw); err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("unexpected answer: %v", resp.Answer)
		}
		return resp, len(raw)
	}
	padding := func(m *dns.Msg) bool {
		if opt := m.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_PADDING); ok {
					return true
				}
			}
		}
		return false
	}

	for _, pass := range []string{"resolved", "cached"} {
		t.Run("DoT, padded query, "+pass, func(t *testing.T) {
			resp, n := ask(t, "tcp-tls", dotAddr, true)
			if !padding(resp) || n%468 != 0 {
				t.Fatalf("reply of %d bytes, padded=%v; want a multiple of 468", n, padding(resp))
			}
		})
	}
	t.Run("DoT, unpadded query", func(t *testing.T) {
		if resp, n := ask(t, "tcp-tls", dotAddr, false); padding(resp) {
			t.Fatalf("padded a %d-byte reply the client did not ask to pad", n)
		}
	})
	t.Run("plain TCP, padded query", func(t *testing.T) {
		if resp, n := ask(t, "tcp", tcpAddr, true); padding(resp) {
			t.Fatalf("padded a %d-byte reply on a clear transport", n)
		}
	})
}
