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

// optCapture is a downstream handler that snapshots the EDNS0_SUBNET
// option (by value) at the moment it sees the chain. A pointer
// snapshot would be misleading: the EDNS middleware reuses the
// request OPT for the outgoing response and now strips ECS from it
// before client write, so any pointer-based assertion read *after*
// ch.Next returns would observe the stripped state, not what
// downstream actually received.
type optCapture struct {
	ecs *dns.EDNS0_SUBNET
}

func (c *optCapture) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if opt := ch.Request.IsEdns0(); opt != nil {
		if sub := findSubnet(opt); sub != nil {
			snap := *sub
			c.ecs = &snap
		}
	}
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

	if got := cap.ecs; got != nil {
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

	got := cap.ecs
	if got == nil {
		t.Fatal("expected ECS to be forwarded to downstream")
	}
	assert.Equal(t, uint8(24), got.SourceNetmask, "ceiling clamp")
	assert.Equal(t, "203.0.113.0", got.Address.String(), "host bits zeroed")
	assert.Equal(t, uint8(0), got.SourceScope, "outgoing SCOPE must be 0")
}

// TestEDNS_ResponseDoesNotLeakForwardedECS pins the P2 fix from the
// ultrareview: with ECS forwarding enabled, the clamped query ECS we
// put on the request OPT for upstream propagation must NOT round-trip
// to the client. Two leak paths exist (resolver re-attaches the
// request OPT to the response, edns merges w.opt.Option into the
// response OPT); the strip in WriteMsg closes both.
func TestEDNS_ResponseDoesNotLeakForwardedECS(t *testing.T) {
	cfg := new(config.Config)
	cfg.ECS = config.ECSConfig{Enabled: true, ForwardV4Max: 24}
	e := New(cfg)

	// Downstream handler mimics the resolver leak path (a): it
	// re-attaches the request OPT — possibly mutated by SetEdns0 to
	// include the forwarded ECS — onto its response message.
	leak := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		req := ch.Request
		resp := new(dns.Msg)
		resp.SetReply(req)
		if opt := req.IsEdns0(); opt != nil {
			resp.Extra = append(resp.Extra, opt)
		}
		_ = ch.Writer.WriteMsg(resp)
	})
	ch := middleware.NewChain([]middleware.Handler{e, leak})

	req := ecsRequest("example.com.", 24, "203.0.113.0")
	mw := mock.NewWriter("udp", "203.0.113.5:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	written := mw.Msg()
	if written == nil {
		t.Fatal("no response written")
	}
	if got := findSubnet(written.IsEdns0()); got != nil {
		t.Errorf("client must not see ECS in response, got %+v", got)
	}
}

// TestEDNS_DisabledOnBadClientNetworks pins the P1 fix from the
// ultrareview. A typo'd CIDR collapses the allow-list to empty under
// the previous silent-drop policy, re-opening the feature to every
// client. The fail-closed build must disable the policy entirely so
// SetEdns0 falls back to strip-everything.
func TestEDNS_DisabledOnBadClientNetworks(t *testing.T) {
	cfg := new(config.Config)
	cfg.ECS = config.ECSConfig{
		Enabled:        true,
		ForwardV4Max:   24,
		ClientNetworks: []string{"10.0.0.0/33"}, // intentional typo
	}
	e := New(cfg)
	if e.ecsPolicy != nil {
		t.Fatal("malformed client_networks must disable the policy")
	}

	cap := &optCapture{}
	ch := middleware.NewChain([]middleware.Handler{e, cap})

	req := ecsRequest("example.com.", 24, "10.0.0.0")
	mw := mock.NewWriter("udp", "10.0.0.5:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())

	if got := cap.ecs; got != nil {
		t.Errorf("disabled policy must strip ECS, got %+v", got)
	}
}

// TestEDNS_DisabledOnOutOfRangeCeiling covers the source-prefix
// validation branch of P1: forward_v4 = 200 is nonsense and must
// disable the policy rather than silently letting Clamp's
// netip.Prefix call fail mid-request.
func TestEDNS_DisabledOnOutOfRangeCeiling(t *testing.T) {
	cfg := new(config.Config)
	cfg.ECS = config.ECSConfig{Enabled: true, ForwardV4Max: 200}
	if got := New(cfg).ecsPolicy; got != nil {
		t.Errorf("out-of-range forward_v4 must disable the policy, got %+v", got)
	}
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

	if got := cap.ecs; got != nil {
		t.Errorf("client outside allow-list should not see ECS forwarded, got %+v", got)
	}
}

// adSetter replies with AuthenticatedData=true, simulating a validated
// answer (or an upstream/forwarder response carrying AD).
type adSetter struct{}

func (a *adSetter) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	m := new(dns.Msg)
	m.SetReply(ch.Request)
	m.AuthenticatedData = true
	_ = ch.Writer.WriteMsg(m)
}
func (a *adSetter) Name() string { return "ad-setter" }

// TestEDNS_ClearsADForCheckingDisabled pins the RFC 4035 §3.2.3 / RFC 6840
// §5.7 rule: a CD=1 client opted out of trusting our validation, so the AD
// bit must never be asserted to it — even if a downstream handler (e.g. the
// forwarder passing an upstream's bit through) set it.
func TestEDNS_ClearsADForCheckingDisabled(t *testing.T) {
	e := New(new(config.Config))
	ch := middleware.NewChain([]middleware.Handler{e, &adSetter{}})

	// CD=1 client (also DO=1) must receive AD=0.
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO=1
	req.CheckingDisabled = true
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(context.Background())
	assert.True(t, mw.Written())
	assert.False(t, mw.Msg().AuthenticatedData, "AD must be cleared for a CD=1 client")

	// Control: DO=1, CD=0 client keeps the validated AD bit.
	req2 := new(dns.Msg)
	req2.SetQuestion("example.com.", dns.TypeA)
	req2.SetEdns0(4096, true) // DO=1
	mw2 := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw2, req2)
	ch.Next(context.Background())
	assert.True(t, mw2.Msg().AuthenticatedData, "AD must survive for a DO=1, CD=0 client")
}
