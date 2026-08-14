package server

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// directPackStub answers every query with a fixed compressed response.
type directPackStub struct{}

func (directPackStub) Name() string { return "direct-pack-stub" }

func (directPackStub) ServeDNS(_ context.Context, ch *middleware.Chain) {
	resp := new(dns.Msg)
	resp.SetReply(ch.Request)
	resp.Compress = true
	rr, err := dns.NewRR("e2e.example. 300 IN A 192.0.2.77")
	if err == nil {
		resp.Answer = []dns.RR{rr}
	}
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

// TestDirectPackOverRealSockets sends real queries through the SDNS-owned
// UDP and TCP listeners, which are constructed with the direct handler: the
// response travels as pooled-packed bytes through the transport's raw Write —
// with its two-byte length prefix on the stream side — and a stock DNS
// client has to parse it as if nothing changed.
func TestDirectPackOverRealSockets(t *testing.T) {
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("direct-pack-stub", func(*config.Config) middleware.Handler {
		return directPackStub{}
	})
	cfg := &config.Config{Bind: "127.0.0.1:0"}
	middleware.Setup(cfg)
	s := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	udp, ok := s.listeners[0].(*udpListener)
	if !ok {
		t.Fatalf("listener 0 is %T, want the UDP listener", s.listeners[0])
	}
	tcp, ok := s.listeners[1].(*tcpListener)
	if !ok {
		t.Fatalf("listener 1 is %T, want the TCP listener", s.listeners[1])
	}
	if err := udp.Bind(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tcp.Bind(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { _ = udp.Serve(ctx) }()
	go func() { _ = tcp.Serve(ctx) }()
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), time.Second)
		defer scancel()
		_ = udp.Shutdown(sctx)
		_ = tcp.Shutdown(sctx)
	})

	udp.mu.Lock()
	udpAddr := udp.pcs[0].LocalAddr().String()
	udp.mu.Unlock()
	tcp.mu.Lock()
	tcpAddr := tcp.ln.Addr().String()
	tcp.mu.Unlock()

	for _, tc := range []struct {
		net  string
		addr string
	}{
		{"udp", udpAddr},
		{"tcp", tcpAddr},
	} {
		t.Run(tc.net, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("e2e.example.", dns.TypeA)

			client := &dns.Client{Net: tc.net, Timeout: 3 * time.Second}
			var resp *dns.Msg
			var err error
			// The listener goroutines may still be coming up.
			for range 20 {
				resp, _, err = client.Exchange(req, tc.addr)
				if err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("exchange over %s: %v", tc.net, err)
			}
			if resp.Id != req.Id {
				t.Fatalf("response ID %d, want %d", resp.Id, req.Id)
			}
			if len(resp.Answer) != 1 || resp.Answer[0].Header().Name != "e2e.example." {
				t.Fatalf("unexpected answer: %v", resp.Answer)
			}
		})
	}
}
