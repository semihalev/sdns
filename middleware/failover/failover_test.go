package failover

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)

	_ = w.WriteMsg(m)
}

func (d *dummy) Name() string { return "dummy" }

func Test_Failover(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	cfg.FallbackServers = []string{"[::255]:53", "8.8.8.8:53", "1"}

	middleware.Register("failover", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	f := middleware.Get("failover").(*Failover)
	assert.Equal(t, "failover", f.Name())

	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	ch.Request = req

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	req.RecursionDesired = true

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeSuccess)

	f.servers = []string{}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)

	f.servers = []string{"[::255]:53"}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, mw.Rcode(), dns.RcodeServerFailure)
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
