package server

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/edns"
)

// paddingStub answers e2e.example. with an address and big.example. with a
// TXT answer sized so the reply, with the OPT the EDNS layer adds, is
// bigReply bytes: a full padding block would carry it past the DNS limit.
type paddingStub struct{}

const bigReply = 65521

func (paddingStub) Name() string { return "padding-stub" }

func (paddingStub) ServeDNS(_ context.Context, ch *middleware.Chain) {
	req := ch.Request.Msg()
	if req.Question[0].Name != "big.example." {
		directPackStub{}.ServeDNS(context.Background(), ch)
		return
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Compress = true
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: "big.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}}
	resp.Answer = []dns.RR{txt}
	// The EDNS layer's OPT is 11 bytes; each string costs its length and
	// one length byte.
	const target = bigReply - 11
	for resp.Len()+256 <= target {
		txt.Txt = append(txt.Txt, strings.Repeat("x", 255))
	}
	if last := target - resp.Len() - 1; last >= 0 {
		txt.Txt = append(txt.Txt, strings.Repeat("y", last))
	}
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

// wrapper stands in for a middleware ahead of EDNS that wraps the writer
// the way dnstap does, by embedding the interface: whatever the concrete
// writer offers beyond it is hidden from everything after.
type wrapper struct{}

type wrappedWriter struct{ middleware.ResponseWriter }

func (wrapper) Name() string { return "wrapper" }

func (wrapper) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w := ch.Writer
	ch.Writer = wrappedWriter{w}
	defer func() { ch.Writer = w }()
	ch.Next(ctx)
}

// A client that pads its query over DoT gets a reply padded to a multiple
// of 468 bytes (RFC 7830, RFC 8467 §4.1), from the resolution, which the
// Msg path writes, and from the cache, which the byte path writes, with a
// writer wrapper ahead of the EDNS layer. A reply a full block would carry
// past the DNS limit is padded only as far as the limit, and delivered.
// Over plain TCP the same query gets no padding, and a DoT client that did
// not pad gets none either.
func TestDoTRepliesArePaddedWhenTheClientPads(t *testing.T) {
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("wrapper", func(*config.Config) middleware.Handler { return wrapper{} })
	middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return edns.New(cfg) })
	middleware.Register("cache", func(cfg *config.Config) middleware.Handler { return cache.New(cfg) })
	middleware.Register("padding-stub", func(*config.Config) middleware.Handler {
		return paddingStub{}
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

	askName := func(t *testing.T, name string, qtype uint16, net, addr string, pad bool) (*dns.Msg, int) {
		t.Helper()
		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
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
	ask := func(t *testing.T, net, addr string, pad bool) (*dns.Msg, int) {
		t.Helper()
		return askName(t, "e2e.example.", dns.TypeA, net, addr, pad)
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

	for _, pass := range []string{"resolved", "cached"} {
		t.Run("DoT, near the DNS limit, padded query, "+pass, func(t *testing.T) {
			resp, n := askName(t, "big.example.", dns.TypeTXT, "tcp-tls", dotAddr, true)
			if n != dns.MaxMsgSize || !padding(resp) {
				t.Fatalf("reply of %d bytes, padded=%v; want padding up to the %d-byte limit",
					n, padding(resp), dns.MaxMsgSize)
			}
		})
	}
	t.Run("DoT, near the DNS limit, unpadded query", func(t *testing.T) {
		if _, n := askName(t, "big.example.", dns.TypeTXT, "tcp-tls", dotAddr, false); n != bigReply {
			t.Fatalf("fixture: reply of %d bytes, want %d", n, bigReply)
		}
	})
}
