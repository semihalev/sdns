package edns

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	m := new(dns.Msg)
	m.SetReply(req)

	rrHeader := dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	a := &dns.A{Hdr: rrHeader, A: net.ParseIP("127.0.0.1")}

	for i := 0; i < 100; i++ {
		m.Answer = append(m.Answer, a)
	}

	_ = w.WriteMsg(m)
}

func (d *dummy) Name() string { return "dummy" }

func Test_EDNS(t *testing.T) {
	testDomain := "example.com."

	cfg := new(config.Config)

	middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	edns := middleware.Get("edns").(*EDNS)
	assert.Equal(t, "edns", edns.Name())

	ch := middleware.NewChain([]middleware.Handler{edns, &dummy{}})

	req := new(dns.Msg)
	req.SetQuestion(testDomain, dns.TypeA)

	mw := mock.NewWriter("tcp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	assert.True(t, ch.Writer.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())
	assert.Nil(t, ch.Writer.Msg().IsEdns0())

	req.SetEdns0(4096, true)
	opt := req.IsEdns0()
	opt.SetVersion(100)

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	assert.True(t, ch.Writer.Written())
	assert.Equal(t, dns.RcodeBadVers, ch.Writer.Rcode())

	opt = req.IsEdns0()
	opt.SetVersion(0)
	opt.SetUDPSize(512)

	mw = mock.NewWriter("tcp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	if assert.True(t, ch.Writer.Written()) {
		assert.False(t, ch.Writer.Msg().Truncated)
	}

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	if assert.True(t, ch.Writer.Written()) {
		assert.True(t, ch.Writer.Msg().Truncated)
	}

	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "testtesttesttest",
	})
	opt.SetUDPSize(4096)
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())
}

// optCapture is a downstream handler that snapshots req.Extra at the
// moment it sees the chain, so a test can assert what the EDNS
// middleware put on the outgoing OPT.
type optCapture struct {
	got *dns.OPT
}

func (c *optCapture) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	c.got = ch.Request.IsEdns0()
	m := new(dns.Msg)
	m.SetReply(ch.Request)
	_ = ch.Writer.WriteMsg(m)
}

func (c *optCapture) Name() string { return "opt-capture" }

func findSubnet(opt *dns.OPT) *dns.EDNS0_SUBNET {
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if v, ok := o.(*dns.EDNS0_SUBNET); ok {
			return v
		}
	}
	return nil
}

func ecsRequest(domain string, src uint8, addr string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(domain, dns.TypeA)
	req.SetEdns0(4096, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1,
		SourceNetmask: src, SourceScope: 0,
		Address: net.ParseIP(addr).To4(),
	})
	return req
}

func TestEDNS_StripsECSWhenPolicyDisabled(t *testing.T) {
	// Default config: ECS disabled. Even if the client sends ECS, the
	// outgoing OPT must not carry it (RFC 7871 §11 default).
	cfg := new(config.Config)
	e := New(cfg)
	cap := &optCapture{}
	ch := middleware.NewChain([]middleware.Handler{e, cap})

	req := ecsRequest("example.com.", 24, "203.0.113.0")
	mw := mock.NewWriter("udp", "203.0.113.5:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	if got := findSubnet(cap.got); got != nil {
		t.Errorf("disabled policy must strip ECS, got %+v", got)
	}
}

func TestEDNS_ForwardsECSClampedDownstream(t *testing.T) {
	// Client sends /28, policy ceiling is /24. The downstream handler
	// must see a /24 with the host bits zeroed — proves the forwarding
	// path round-trips through middleware/edns end-to-end.
	cfg := new(config.Config)
	cfg.ECS = config.ECSConfig{
		Enabled:      true,
		ForwardV4Max: 24,
		ForwardV6Max: 56,
	}
	e := New(cfg)
	cap := &optCapture{}
	ch := middleware.NewChain([]middleware.Handler{e, cap})

	req := ecsRequest("example.com.", 28, "203.0.113.42")
	mw := mock.NewWriter("udp", "203.0.113.42:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	got := findSubnet(cap.got)
	if got == nil {
		t.Fatal("expected ECS to be forwarded to downstream")
	}
	assert.Equal(t, uint8(24), got.SourceNetmask, "ceiling clamp")
	assert.Equal(t, "203.0.113.0", got.Address.String(), "host bits zeroed")
	assert.Equal(t, uint8(0), got.SourceScope, "outgoing SCOPE must be 0")
}

func TestEDNS_ForwardsECSGatedByClientNetworks(t *testing.T) {
	// Same policy but with a client_networks gate that excludes the
	// test client. Forwarding must stop even though policy is enabled.
	cfg := new(config.Config)
	cfg.ECS = config.ECSConfig{
		Enabled:        true,
		ForwardV4Max:   24,
		ClientNetworks: []string{"10.0.0.0/8"},
	}
	e := New(cfg)
	cap := &optCapture{}
	ch := middleware.NewChain([]middleware.Handler{e, cap})

	req := ecsRequest("example.com.", 24, "203.0.113.0")
	mw := mock.NewWriter("udp", "203.0.113.5:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	if got := findSubnet(cap.got); got != nil {
		t.Errorf("client outside allow-list should not see ECS forwarded, got %+v", got)
	}
}
