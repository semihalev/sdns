package dns64

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/util"
	"github.com/stretchr/testify/assert"
)

// stubQueryer is a fixed-response Queryer used to drive the
// secondary A-record lookup in tests.
type stubQueryer struct {
	resp *dns.Msg
	err  error
	last *dns.Msg
}

func (s *stubQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	s.last = req
	if s.err != nil {
		return nil, s.err
	}
	if s.resp == nil {
		return nil, nil
	}
	return s.resp, nil
}

// stubAnswerer writes a fixed dns.Msg when its turn in the chain
// comes. Used as the downstream "resolver" so the dns64 wrapper
// observes a real response.
type stubAnswerer struct {
	msg *dns.Msg
}

func (s *stubAnswerer) Name() string { return "stubAnswerer" }
func (s *stubAnswerer) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if s.msg == nil {
		ch.Cancel()
		return
	}
	resp := s.msg.Copy()
	resp.Id = ch.Request.Id
	resp.Question = ch.Request.Question
	resp.Response = true
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

// baseConfig returns a minimal DNS64 config with the well-known
// prefix and an empty client_networks list (i.e. all clients
// eligible).
func baseConfig() *config.Config {
	return &config.Config{
		DNS64: config.DNS64Config{
			Enabled:  true,
			Prefixes: []string{"64:ff9b::/96"},
			ExcludeANetworks: []string{
				"10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8",
			},
		},
	}
}

// makeChain wires a dns64 handler in front of the given downstream
// answerer with a mock writer addressed from clientAddr. EDNS0 is
// attached to the request so EDE attachment paths are exercised.
func makeChain(t *testing.T, d *DNS64, downstream middleware.Handler, clientAddr, qname string, qtype uint16) (*middleware.Chain, *mock.Writer) {
	t.Helper()
	ch := middleware.NewChain([]middleware.Handler{d, downstream})
	mw := mock.NewWriter("udp", clientAddr)
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	req.SetEdns0(4096, true)
	ch.Reset(mw, req)
	return ch, mw
}

// noDataMsg returns a NOERROR/NODATA response with an SOA in the
// Authority section carrying the given negative TTL.
func noDataMsg(qname string, soaMin uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeAAAA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	m.RecursionAvailable = true
	m.SetEdns0(4096, true)
	soa, _ := dns.NewRR("example.org. 3600 IN SOA ns.example.org. hostmaster.example.org. 1 7200 3600 604800 " + uintToString(soaMin))
	m.Ns = []dns.RR{soa}
	return m
}

// nxDomainMsg returns an NXDOMAIN response.
func nxDomainMsg(qname string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeAAAA)
	m.Response = true
	m.Rcode = dns.RcodeNameError
	m.RecursionAvailable = true
	m.SetEdns0(4096, true)
	return m
}

// aRespMsg builds an A-record response for use as the stub
// queryer's reply.
func aRespMsg(qname string, ttl uint32, ips ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	m.RecursionAvailable = true
	for _, ip := range ips {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(ip),
		})
	}
	return m
}

func uintToString(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestDNS64_DisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	if d := New(cfg); d != nil {
		t.Fatalf("disabled DNS64 should return typed-nil, got %#v", d)
	}
}

func TestDNS64_ClientOnly(t *testing.T) {
	d := New(baseConfig())
	if d == nil {
		t.Fatalf("expected non-nil DNS64 handler")
	}
	if !d.ClientOnly() {
		t.Fatalf("DNS64 must be ClientOnly() == true")
	}
}

func TestServeDNS_NonAAAA_FallsThrough(t *testing.T) {
	d := New(baseConfig())
	downstream := &stubAnswerer{msg: aRespMsg("foo.example.org.", 60, "192.0.2.1")}
	ch, mw := makeChain(t, d, downstream, "203.0.113.5:53", "foo.example.org.", dns.TypeA)
	d.queryer = &stubQueryer{} // should not be invoked

	d.ServeDNS(context.Background(), ch)
	assert.True(t, mw.Written())
	resp := mw.Msg()
	if assert.NotNil(t, resp) {
		assert.Equal(t, dns.TypeA, resp.Answer[0].Header().Rrtype)
	}
}

func TestServeDNS_PassThrough_NonEmptyAAAA(t *testing.T) {
	d := New(baseConfig())
	aaaaResp := new(dns.Msg)
	aaaaResp.SetQuestion("foo.example.org.", dns.TypeAAAA)
	aaaaResp.Response = true
	aaaaResp.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2001:db8::1"),
	}}
	downstream := &stubAnswerer{msg: aaaaResp}
	q := &stubQueryer{}
	d.queryer = q

	ch, mw := makeChain(t, d, downstream, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	assert.True(t, mw.Written())
	if q.last != nil {
		t.Fatalf("non-empty AAAA must not trigger an A lookup; queryer was called with %+v", q.last)
	}
	resp := mw.Msg()
	assert.Len(t, resp.Answer, 1)
	assert.Equal(t, "2001:db8::1", resp.Answer[0].(*dns.AAAA).AAAA.String())
}

func TestServeDNS_Internal_NoSynth(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.1")}

	ch := middleware.NewChain([]middleware.Handler{d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}})
	mw := mock.NewWriter("udp", "127.0.0.255:0") // sentinel internal IP
	req := new(dns.Msg)
	req.SetQuestion("foo.example.org.", dns.TypeAAAA)
	req.SetEdns0(4096, true)
	ch.Reset(mw, req)

	d.ServeDNS(context.Background(), ch)
	assert.True(t, mw.Written())
	resp := mw.Msg()
	// Pass-through: original NODATA is preserved, no AAAA in answer.
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			t.Fatalf("internal query must not be synthesised, but got AAAA %s", rr)
		}
	}
}

func TestServeDNS_CDBit_NoSynth(t *testing.T) {
	d := New(baseConfig())
	q := &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.1")}
	d.queryer = q

	ch := middleware.NewChain([]middleware.Handler{d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}})
	mw := mock.NewWriter("udp", "203.0.113.5:53")
	req := new(dns.Msg)
	req.SetQuestion("foo.example.org.", dns.TypeAAAA)
	req.SetEdns0(4096, true)
	req.CheckingDisabled = true
	ch.Reset(mw, req)

	d.ServeDNS(context.Background(), ch)
	assert.True(t, mw.Written())
	if q.last != nil {
		t.Fatalf("CD=1 must not trigger A lookup")
	}
}

func TestServeDNS_ClientOutsideNetworks_NoSynth(t *testing.T) {
	cfg := baseConfig()
	cfg.DNS64.ClientNetworks = []string{"2001:db8::/32"}
	d := New(cfg)
	q := &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.1")}
	d.queryer = q

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)
	assert.True(t, mw.Written())
	if q.last != nil {
		t.Fatalf("client outside client_networks must not trigger A lookup")
	}
}

func TestServeDNS_ZoneExcluded_NoSynth(t *testing.T) {
	cfg := baseConfig()
	cfg.DNS64.ExcludeZones = []string{"example.org."}
	d := New(cfg)
	q := &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.1")}
	d.queryer = q

	ch, _ := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)
	if q.last != nil {
		t.Fatalf("excluded zone must not trigger A lookup")
	}
}

func TestSynthesise_NODATA_HasA(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 600, "192.0.2.33")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	assert.True(t, mw.Written())
	resp := mw.Msg()
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	if assert.Len(t, resp.Answer, 1) {
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if assert.True(t, ok) {
			assert.Equal(t, "64:ff9b::c000:221", aaaa.AAAA.String())
			// SOA-min (300) is lower than A TTL (600), so the
			// synth TTL is clamped to 300.
			assert.Equal(t, uint32(300), aaaa.Hdr.Ttl)
			assert.Equal(t, "foo.example.org.", aaaa.Hdr.Name)
		}
	}
}

// TestNXDOMAIN_PassesThrough pins RFC 6147 §5.1.2: an upstream
// NXDOMAIN means the name doesn't exist (so it can have no A
// either), and DNS64 must forward it unchanged. A queryer that
// would have returned A records is provided to confirm we never
// reach the synthesis path.
func TestNXDOMAIN_PassesThrough(t *testing.T) {
	d := New(baseConfig())
	q := &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}
	d.queryer = q

	ch, mw := makeChain(t, d, &stubAnswerer{msg: nxDomainMsg("foo.example.org.")}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.Equal(t, dns.RcodeNameError, resp.Rcode, "NXDOMAIN must pass through unchanged per RFC 6147 §5.1.2")
	if q.last != nil {
		t.Fatalf("NXDOMAIN must not trigger an A-record lookup; queryer was called")
	}
}

// TestServFail_TriggersSynthesis pins RFC 6147 §5.1.3: nonzero
// RCODEs other than NXDOMAIN are treated as "no answer" and the
// secondary A lookup is attempted. Backwards-compatible with
// upstreams that return SERVFAIL for AAAA on broken zones.
func TestServFail_TriggersSynthesis(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}

	servfail := new(dns.Msg)
	servfail.SetQuestion("foo.example.org.", dns.TypeAAAA)
	servfail.Response = true
	servfail.Rcode = dns.RcodeServerFailure
	servfail.SetEdns0(4096, true)

	ch, mw := makeChain(t, d, &stubAnswerer{msg: servfail}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	if assert.Len(t, resp.Answer, 1) {
		aaaa := resp.Answer[0].(*dns.AAAA)
		assert.Equal(t, "64:ff9b::c000:221", aaaa.AAAA.String())
	}
}

func TestSynthesise_QueryerError_FallsBack(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{err: errors.New("simulated upstream failure")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	// Original NODATA preserved.
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			t.Fatalf("queryer error must not produce synthesised AAAA")
		}
	}
}

func TestSynthesise_AD_AddsEDE(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}

	orig := noDataMsg("foo.example.org.", 300)
	orig.AuthenticatedData = true
	ch, mw := makeChain(t, d, &stubAnswerer{msg: orig}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)

	d.ServeDNS(context.Background(), ch)
	resp := mw.Msg()
	assert.False(t, resp.AuthenticatedData, "synthesised reply must clear AD")

	ede := util.GetEDE(resp)
	if assert.NotNil(t, ede, "EDE 4 should be attached when original was AD=1") {
		assert.Equal(t, dns.ExtendedErrorCodeForgedAnswer, ede.InfoCode)
	}
}

func TestSynthesise_NoAD_NoEDE(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)
	resp := mw.Msg()
	assert.Nil(t, util.GetEDE(resp), "EDE must NOT be attached when original was AD=0")
}

func TestSynthesise_PrivateA_WellKnownPrefix_AllExcluded(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "10.0.0.1")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			t.Fatalf("RFC 6147 §5.1.4: private A under well-known prefix must not be synthesised")
		}
	}
}

func TestSynthesise_PrivateA_OperatorPrefix_Synth(t *testing.T) {
	cfg := baseConfig()
	cfg.DNS64.Prefixes = []string{"2001:db8:64::/96"}
	cfg.DNS64.ExcludeANetworks = nil
	d := New(cfg)
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "10.0.0.1")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 1) {
		aaaa := resp.Answer[0].(*dns.AAAA)
		assert.Equal(t, "2001:db8:64::a00:1", aaaa.AAAA.String())
	}
}

// TestSynthesise_TTL_ATtlIsLower pins RFC 6147 §5.1.7: the synth
// TTL is the lower of the A TTL and the SOA negative-cache TTL.
// No artificial floor — a 30s A record produces a 30s AAAA.
func TestSynthesise_TTL_ATtlIsLower(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 30, "192.0.2.33")}
	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 7200)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)
	aaaa := mw.Msg().Answer[0].(*dns.AAAA)
	assert.Equal(t, uint32(30), aaaa.Hdr.Ttl)
}

// TestSynthesise_TTL_NegativeIsLower covers the symmetric case:
// SOA min smaller than A TTL → SOA min wins.
func TestSynthesise_TTL_NegativeIsLower(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 600, "192.0.2.33")}
	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 120)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)
	aaaa := mw.Msg().Answer[0].(*dns.AAAA)
	assert.Equal(t, uint32(120), aaaa.Hdr.Ttl)
}

// TestSynthesise_TTL_NoSOA_Caps600 pins RFC 6147 §5.1.7: when
// no SOA is present in the upstream NODATA, the synth TTL caps at
// 600 even if A TTL is higher.
func TestSynthesise_TTL_NoSOA_Caps600(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 7200, "192.0.2.33")}

	// NODATA without an SOA in Authority.
	noSOA := new(dns.Msg)
	noSOA.SetQuestion("foo.example.org.", dns.TypeAAAA)
	noSOA.Response = true
	noSOA.Rcode = dns.RcodeSuccess
	noSOA.SetEdns0(4096, true)

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noSOA}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)
	aaaa := mw.Msg().Answer[0].(*dns.AAAA)
	assert.Equal(t, uint32(600), aaaa.Hdr.Ttl, "no-SOA AAAA must cap synth TTL at 600 per RFC 6147 §5.1.7")
}

func TestSynthesise_CnameChain(t *testing.T) {
	d := New(baseConfig())
	aResp := new(dns.Msg)
	aResp.SetQuestion("alias.example.org.", dns.TypeA)
	aResp.Response = true
	aResp.Rcode = dns.RcodeSuccess
	cname, _ := dns.NewRR("alias.example.org. 60 IN CNAME target.example.org.")
	aResp.Answer = []dns.RR{
		cname,
		&dns.A{
			Hdr: dns.RR_Header{Name: "target.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.33"),
		},
	}
	d.queryer = &stubQueryer{resp: aResp}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("alias.example.org.", 300)}, "203.0.113.5:53", "alias.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 2) {
		_, isCNAME := resp.Answer[0].(*dns.CNAME)
		aaaa, isAAAA := resp.Answer[1].(*dns.AAAA)
		assert.True(t, isCNAME, "first answer record must be the CNAME")
		if assert.True(t, isAAAA) {
			assert.Equal(t, "target.example.org.", aaaa.Hdr.Name, "synthesised AAAA must be owned by the CNAME target")
			assert.Equal(t, "64:ff9b::c000:221", aaaa.AAAA.String())
		}
	}
}

func TestSynthesise_MultipleAs_AllSynthesised(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33", "203.0.113.7")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	count := 0
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			count++
		}
	}
	assert.Equal(t, 2, count, "every A record should produce a synthesised AAAA")
}

// TestSynthesise_RetainsOPT pins the behaviour that lets EDE
// attachment work — without OPT in Extra, util.SetEDE is a no-op
// so the AD-bit downgrade would silently drop its rationale.
func TestSynthesise_RetainsOPT(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)
	assert.NotNil(t, mw.Msg().IsEdns0(), "synthesised response must carry OPT")
}

// TestExcludedAAAA_TriggersSynthesis pins RFC 6147 §5.1.4: an
// upstream that returns only IPv4-mapped AAAA records must be
// treated as "no AAAA" so DNS64 falls through to synthesis from
// the A side.
func TestExcludedAAAA_TriggersSynthesis(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}

	upstream := new(dns.Msg)
	upstream.SetQuestion("foo.example.org.", dns.TypeAAAA)
	upstream.Response = true
	upstream.SetEdns0(4096, true)
	// IPv4-mapped IPv6: ::ffff:c000:221 is the wire form of 192.0.2.33.
	upstream.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("::ffff:c000:221"),
	}}
	ch, mw := makeChain(t, d, &stubAnswerer{msg: upstream}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 1) {
		aaaa := resp.Answer[0].(*dns.AAAA)
		assert.Equal(t, "64:ff9b::c000:221", aaaa.AAAA.String(), "IPv4-mapped AAAA was excluded; synthesised AAAA used instead")
	}
}

// TestExcludedAAAA_StripsButPassesThrough covers the partial-
// exclusion case: at least one AAAA survives the filter, so the
// response is still pass-through, but excluded AAAAs are dropped
// from Answer before reaching the client.
func TestExcludedAAAA_StripsButPassesThrough(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{} // would loudly fail if called

	upstream := new(dns.Msg)
	upstream.SetQuestion("foo.example.org.", dns.TypeAAAA)
	upstream.Response = true
	upstream.SetEdns0(4096, true)
	upstream.Answer = []dns.RR{
		&dns.AAAA{ // excluded
			Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("::ffff:c000:221"),
		},
		&dns.AAAA{ // routable
			Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}
	ch, mw := makeChain(t, d, &stubAnswerer{msg: upstream}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 1, "excluded AAAA must be stripped, routable one preserved") {
		aaaa := resp.Answer[0].(*dns.AAAA)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	}
}

// TestExcludedAAAA_OptOutEmptyList confirms an explicit empty
// exclude_aaaa_networks (declared in TOML as []) opts out of
// filtering — the IPv4-mapped AAAA reaches the client unchanged.
func TestExcludedAAAA_OptOutEmptyList(t *testing.T) {
	cfg := baseConfig()
	cfg.DNS64.ExcludeAAAANetworks = []string{} // explicit empty
	d := New(cfg)
	d.queryer = &stubQueryer{}

	upstream := new(dns.Msg)
	upstream.SetQuestion("foo.example.org.", dns.TypeAAAA)
	upstream.Response = true
	upstream.SetEdns0(4096, true)
	upstream.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("::ffff:c000:221"),
	}}
	ch, mw := makeChain(t, d, &stubAnswerer{msg: upstream}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 1) {
		aaaa := resp.Answer[0].(*dns.AAAA)
		// net.IP.String prints IPv4-mapped IPv6 in dotted form, so
		// compare via Equal against the canonical 16-byte form.
		assert.True(t, aaaa.AAAA.Equal(net.ParseIP("::ffff:c000:221")),
			"with filter disabled, IPv4-mapped AAAA passes through; got %s", aaaa.AAAA)
	}
}

// TestSynthesise_ANXDOMAIN_BecomesClientResponse pins RFC 6147
// §5.1.6: when the AAAA returned NODATA but the secondary A
// query yielded NXDOMAIN, the A NXDOMAIN — not the original
// AAAA NODATA — is the basis for the client reply.
func TestSynthesise_ANXDOMAIN_BecomesClientResponse(t *testing.T) {
	d := New(baseConfig())
	nx := new(dns.Msg)
	nx.SetQuestion("foo.example.org.", dns.TypeA)
	nx.Response = true
	nx.Rcode = dns.RcodeNameError
	soa, _ := dns.NewRR("example.org. 3600 IN SOA ns. host. 1 7200 3600 604800 60")
	nx.Ns = []dns.RR{soa}
	d.queryer = &stubQueryer{resp: nx}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.Equal(t, dns.RcodeNameError, resp.Rcode, "client sees the A NXDOMAIN promoted to AAAA")
	assert.Empty(t, resp.Answer)
	assert.Equal(t, dns.TypeAAAA, resp.Question[0].Qtype)
}

// TestSynthesise_AuthorityFromAResponse pins RFC 6147 §5.4: the
// Authority section of the synthesised reply comes from the final
// A response, not the original AAAA NODATA. The SOA-min in the
// AAAA NODATA still drives the synth TTL via §5.1.7, but the
// Authority records served to the client are the A-side ones.
func TestSynthesise_AuthorityFromAResponse(t *testing.T) {
	d := New(baseConfig())
	aResp := aRespMsg("foo.example.org.", 60, "192.0.2.33")
	aSOA, _ := dns.NewRR("example.org. 7200 IN SOA ns.example.org. host.example.org. 42 7200 3600 604800 60")
	aResp.Ns = []dns.RR{aSOA}
	d.queryer = &stubQueryer{resp: aResp}

	orig := noDataMsg("foo.example.org.", 300)
	// Override the original SOA with a different serial so we can
	// detect which one survived in the synthesised reply.
	origSOA, _ := dns.NewRR("example.org. 3600 IN SOA ns.original. host.original. 99 7200 3600 604800 300")
	orig.Ns = []dns.RR{origSOA}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: orig}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Ns, 1, "exactly one SOA from the A response") {
		soa, ok := resp.Ns[0].(*dns.SOA)
		if assert.True(t, ok) {
			assert.Equal(t, uint32(42), soa.Serial, "Authority SOA must come from the A response (serial 42), not original AAAA (serial 99)")
		}
	}
}

// TestDNSSECFailure_PassesThrough pins RFC 6147 §5.5: when the
// upstream resolver returns SERVFAIL with a DNSSEC-failure EDE
// (Bogus, Signature Expired, etc.), DNS64 must surface the
// failure to the client unchanged. Synthesising over a
// validation failure would let an attacker bypass DNSSEC by
// poisoning the AAAA path while keeping the A path clean.
func TestDNSSECFailure_PassesThrough(t *testing.T) {
	codes := []uint16{
		dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm,
		dns.ExtendedErrorCodeUnsupportedDSDigestType,
		dns.ExtendedErrorCodeDNSSECIndeterminate,
		dns.ExtendedErrorCodeDNSBogus,
		dns.ExtendedErrorCodeSignatureExpired,
		dns.ExtendedErrorCodeSignatureNotYetValid,
		dns.ExtendedErrorCodeDNSKEYMissing,
		dns.ExtendedErrorCodeRRSIGsMissing,
		dns.ExtendedErrorCodeNoZoneKeyBitSet,
		dns.ExtendedErrorCodeNSECMissing,
		dns.ExtendedErrorCodeUnsupportedNSEC3IterValue,
	}
	for _, code := range codes {
		t.Run(dns.ExtendedErrorCodeToString[code], func(t *testing.T) {
			d := New(baseConfig())
			q := &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}
			d.queryer = q

			servfail := new(dns.Msg)
			servfail.SetQuestion("foo.example.org.", dns.TypeAAAA)
			servfail.Response = true
			servfail.Rcode = dns.RcodeServerFailure
			servfail.SetEdns0(4096, true)
			util.SetEDE(servfail, code, "")

			ch, mw := makeChain(t, d, &stubAnswerer{msg: servfail}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
			d.ServeDNS(context.Background(), ch)

			resp := mw.Msg()
			assert.Equal(t, dns.RcodeServerFailure, resp.Rcode, "DNSSEC failure must surface to client unchanged")
			if q.last != nil {
				t.Fatalf("DNSSEC failure must not trigger an A lookup; queryer was called")
			}
			ede := util.GetEDE(resp)
			if assert.NotNil(t, ede, "EDE must reach the client") {
				assert.Equal(t, code, ede.InfoCode)
			}
		})
	}
}

// TestServFail_NonDNSSEC_StillSynthesises confirms that a plain
// transport-level SERVFAIL (no DNSSEC EDE) still triggers the
// §5.1.3 "treat as empty answer" path. DNSSEC pass-through must
// be gated on the EDE, not on SERVFAIL alone.
func TestServFail_NonDNSSEC_StillSynthesises(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}

	servfail := new(dns.Msg)
	servfail.SetQuestion("foo.example.org.", dns.TypeAAAA)
	servfail.Response = true
	servfail.Rcode = dns.RcodeServerFailure
	servfail.SetEdns0(4096, true)
	// No DNSSEC EDE attached — represents a plain network
	// SERVFAIL where synthesis is still permissible.

	ch, mw := makeChain(t, d, &stubAnswerer{msg: servfail}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	if assert.Len(t, resp.Answer, 1) {
		aaaa := resp.Answer[0].(*dns.AAAA)
		assert.Equal(t, "64:ff9b::c000:221", aaaa.AAAA.String())
	}
}

// TestRD0_PassesThrough pins the RD=0 escape hatch: a client
// that didn't ask for recursion must reach the rest of the chain
// untouched, so DNS64 doesn't smuggle a recursive secondary
// lookup past the client's intent.
func TestRD0_PassesThrough(t *testing.T) {
	d := New(baseConfig())
	q := &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}
	d.queryer = q

	answered := false
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		answered = true
		// Mimic the cache middleware's RD=0 rejection.
		ch.CancelWithRcode(dns.RcodeServerFailure, false)
	})

	ch := middleware.NewChain([]middleware.Handler{d, downstream})
	mw := mock.NewWriter("udp", "203.0.113.5:53")
	req := new(dns.Msg)
	req.SetQuestion("foo.example.org.", dns.TypeAAAA)
	req.SetEdns0(4096, true)
	req.RecursionDesired = false
	ch.Reset(mw, req)

	d.ServeDNS(context.Background(), ch)

	assert.True(t, answered, "RD=0 must reach the rest of the chain")
	assert.Equal(t, dns.RcodeServerFailure, mw.Msg().Rcode, "downstream rejection passes through verbatim")
	if q.last != nil {
		t.Fatalf("RD=0 must not trigger an A lookup; queryer was called")
	}
}

// TestSynthesise_AResponseAsBasis_PreservesCNAME pins RFC 6147
// §5.1.5: when the A response carries a CNAME chain that ends at
// a name with no A records, the chain must survive into the
// client's reply even though no AAAAs are synthesised. Otherwise
// the client sees a bare NODATA at the original qname while the
// resolver actually walked an alias.
func TestSynthesise_AResponseAsBasis_PreservesCNAME(t *testing.T) {
	d := New(baseConfig())
	aResp := new(dns.Msg)
	aResp.SetQuestion("alias.example.org.", dns.TypeA)
	aResp.Response = true
	aResp.Rcode = dns.RcodeSuccess
	cname, _ := dns.NewRR("alias.example.org. 60 IN CNAME target.example.org.")
	soa, _ := dns.NewRR("example.org. 3600 IN SOA ns. host. 1 7200 3600 604800 60")
	aResp.Answer = []dns.RR{cname}
	aResp.Ns = []dns.RR{soa}
	d.queryer = &stubQueryer{resp: aResp}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("alias.example.org.", 300)}, "203.0.113.5:53", "alias.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	if assert.Len(t, resp.Answer, 1, "CNAME from A response must reach the client") {
		c, ok := resp.Answer[0].(*dns.CNAME)
		if assert.True(t, ok) {
			assert.Equal(t, "target.example.org.", c.Target)
		}
	}
	assert.Equal(t, dns.TypeAAAA, resp.Question[0].Qtype, "client sees its original AAAA question")
}

// TestSynthesise_AdditionalARecordsPassThrough pins RFC 6147
// §5.3.2: A records anywhere except the Answer section must
// reach the client unmodified. This catches the regression where
// extra-section A records were being rewritten into synthetic
// AAAAs.
func TestSynthesise_AdditionalARecordsPassThrough(t *testing.T) {
	d := New(baseConfig())
	aResp := aRespMsg("foo.example.org.", 60, "192.0.2.33")
	// Stuff a glue-style A into Additional. §5.3.2 says it MUST
	// reach the client unchanged — neither dropped nor rewritten.
	gluedA, _ := dns.NewRR("ns.example.org. 60 IN A 198.51.100.7")
	aResp.Extra = []dns.RR{gluedA}
	d.queryer = &stubQueryer{resp: aResp}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	// Find the additional-section A; OPT may also be present.
	var found *dns.A
	for _, rr := range resp.Extra {
		if a, ok := rr.(*dns.A); ok {
			found = a
		}
		if _, ok := rr.(*dns.AAAA); ok {
			t.Fatalf("§5.3.2: Additional section must not contain a synthesised AAAA, got %s", rr)
		}
	}
	if assert.NotNil(t, found, "extra-section A must be passed through unchanged") {
		assert.Equal(t, "198.51.100.7", found.A.String())
		assert.Equal(t, "ns.example.org.", found.Hdr.Name)
	}
}

// TestSynthesise_AuthorityARecordsPassThrough pins the same rule
// for the Authority section: A records there are not touched.
// Authority A records are unusual in real responses but covered
// by §5.3.2 ("DNS64 MUST NOT modify any RRtype other than CNAME
// and RRSIG").
func TestSynthesise_AuthorityARecordsPassThrough(t *testing.T) {
	d := New(baseConfig())
	aResp := aRespMsg("foo.example.org.", 60, "192.0.2.33")
	aSOA, _ := dns.NewRR("example.org. 7200 IN SOA ns.example.org. host.example.org. 42 7200 3600 604800 60")
	authA, _ := dns.NewRR("ns.example.org. 60 IN A 198.51.100.42")
	aResp.Ns = []dns.RR{aSOA, authA}
	d.queryer = &stubQueryer{resp: aResp}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	var foundA *dns.A
	for _, rr := range resp.Ns {
		if a, ok := rr.(*dns.A); ok {
			foundA = a
		}
		if _, ok := rr.(*dns.AAAA); ok {
			t.Fatalf("§5.3.2: Authority section must not contain a synthesised AAAA, got %s", rr)
		}
	}
	if assert.NotNil(t, foundA) {
		assert.Equal(t, "198.51.100.42", foundA.A.String())
	}
}

// TestPassThrough_FilteredAAAAClearsAD pins the §5.1.4 modify-
// the-RRset case: when DNS64 strips IPv4-mapped AAAA records but
// at least one survives, the response we forward differs from
// what the validator signed, so AD must be cleared.
func TestPassThrough_FilteredAAAAClearsAD(t *testing.T) {
	d := New(baseConfig())

	upstream := new(dns.Msg)
	upstream.SetQuestion("foo.example.org.", dns.TypeAAAA)
	upstream.Response = true
	upstream.AuthenticatedData = true
	upstream.SetEdns0(4096, true)
	upstream.Answer = []dns.RR{
		&dns.AAAA{ // excluded → triggers strip
			Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("::ffff:c000:221"),
		},
		&dns.AAAA{ // routable → survives
			Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}
	ch, mw := makeChain(t, d, &stubAnswerer{msg: upstream}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.False(t, resp.AuthenticatedData, "AD must clear after RRset modification")
	if ede := util.GetEDE(resp); assert.NotNil(t, ede, "EDE 4 should be attached when AD was set on the upstream") {
		assert.Equal(t, dns.ExtendedErrorCodeForgedAnswer, ede.InfoCode)
	}
}

// TestPassThrough_NoStripPreservesAD confirms a clean pass-through
// (no AAAA stripped) does NOT clear AD — the RRset is exactly
// what the validator signed.
func TestPassThrough_NoStripPreservesAD(t *testing.T) {
	d := New(baseConfig())

	upstream := new(dns.Msg)
	upstream.SetQuestion("foo.example.org.", dns.TypeAAAA)
	upstream.Response = true
	upstream.AuthenticatedData = true
	upstream.SetEdns0(4096, true)
	upstream.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: "foo.example.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2001:db8::1"),
	}}
	ch, mw := makeChain(t, d, &stubAnswerer{msg: upstream}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	assert.True(t, resp.AuthenticatedData, "AD must survive a clean pass-through")
}

// TestSynthesise_MultiPrefix pins RFC 6147 §5.2: multiple
// configured prefixes each yield a synthesised AAAA per A record,
// so a client receives every reachable path.
func TestSynthesise_MultiPrefix(t *testing.T) {
	cfg := baseConfig()
	cfg.DNS64.Prefixes = []string{"64:ff9b::/96", "2001:db8:64::/96"}
	d := New(cfg)
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "192.0.2.33")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 2, "one synthesised AAAA per configured prefix") {
		assert.Equal(t, "64:ff9b::c000:221", resp.Answer[0].(*dns.AAAA).AAAA.String())
		assert.Equal(t, "2001:db8:64::c000:221", resp.Answer[1].(*dns.AAAA).AAAA.String())
	}
}

// TestSynthesise_MultiPrefix_PerPrefixExclusion confirms the
// IPv4 exclusion list is per-prefix: a private A is excluded
// under 64:ff9b::/96 but synthesised under an operator prefix
// listed alongside it.
func TestSynthesise_MultiPrefix_PerPrefixExclusion(t *testing.T) {
	cfg := baseConfig()
	cfg.DNS64.Prefixes = []string{"64:ff9b::/96", "2001:db8:64::/96"}
	d := New(cfg)
	d.queryer = &stubQueryer{resp: aRespMsg("foo.example.org.", 60, "10.0.0.1")}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("foo.example.org.", 300)}, "203.0.113.5:53", "foo.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 1, "private A excluded under well-known, kept under operator prefix") {
		assert.Equal(t, "2001:db8:64::a00:1", resp.Answer[0].(*dns.AAAA).AAAA.String())
	}
}

// TestPTR_TranslatesUnderWellKnown covers the happy path for
// RFC 6147 §5.3.1: an ip6.arpa PTR for an address inside
// 64:ff9b::/96 yields a CNAME to the corresponding in-addr.arpa.
// The chase response is appended when present.
func TestPTR_TranslatesUnderWellKnown(t *testing.T) {
	d := New(baseConfig())
	// Stub PTR response for the corresponding in-addr.arpa.
	ptrResp := new(dns.Msg)
	ptrResp.SetQuestion("33.2.0.192.in-addr.arpa.", dns.TypePTR)
	ptrResp.Response = true
	ptrResp.Rcode = dns.RcodeSuccess
	rr, _ := dns.NewRR("33.2.0.192.in-addr.arpa. 600 IN PTR target.example.com.")
	ptrResp.Answer = []dns.RR{rr}
	d.queryer = &stubQueryer{resp: ptrResp}

	// 192.0.2.33 embedded in 64:ff9b::/96 is 64:ff9b::c000:221.
	// Reverse: 1.2.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.
	qname := "1.2.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa."

	ch, mw := makeChain(t, d, &stubAnswerer{msg: nil}, "203.0.113.5:53", qname, dns.TypePTR)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if !assert.NotNil(t, resp, "PTR translation must produce a response") {
		return
	}
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	if assert.GreaterOrEqual(t, len(resp.Answer), 1) {
		cname, ok := resp.Answer[0].(*dns.CNAME)
		if assert.True(t, ok, "first answer must be a CNAME") {
			assert.Equal(t, qname, cname.Hdr.Name)
			assert.Equal(t, "33.2.0.192.in-addr.arpa.", cname.Target)
		}
	}
	if assert.Len(t, resp.Answer, 2, "chase result must be appended") {
		ptr, ok := resp.Answer[1].(*dns.PTR)
		if assert.True(t, ok) {
			assert.Equal(t, "target.example.com.", ptr.Ptr)
		}
	}
}

// TestPTR_NoMatchFallsThrough confirms PTR queries for ip6.arpa
// names whose address lies outside every configured Pref64 are
// passed to the rest of the chain (so real reverse zones still
// answer normally).
func TestPTR_NoMatchFallsThrough(t *testing.T) {
	d := New(baseConfig())
	d.queryer = &stubQueryer{} // would loudly fail if called

	// Address outside 64:ff9b::/96 — operator chose a different
	// prefix elsewhere; this address shouldn't be translated by us.
	qname := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."

	answered := false
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		answered = true
		// Emulate a normal NXDOMAIN from the real zone.
		nxd := new(dns.Msg)
		nxd.SetRcode(ch.Request, dns.RcodeNameError)
		nxd.Response = true
		_ = ch.Writer.WriteMsg(nxd)
		ch.Cancel()
	})
	ch, mw := makeChain(t, d, downstream, "203.0.113.5:53", qname, dns.TypePTR)
	d.ServeDNS(context.Background(), ch)

	assert.True(t, answered, "downstream must run when PTR is not under a configured Pref64")
	assert.Equal(t, dns.RcodeNameError, mw.Msg().Rcode)
}

// TestPTR_ExcludedV4SkipsTranslation pins RFC 6147 §5.1.4
// symmetry: a PTR whose embedded IPv4 is in the well-known
// exclude list flows through normal recursion instead of being
// rewritten.
func TestPTR_ExcludedV4SkipsTranslation(t *testing.T) {
	d := New(baseConfig())

	// 10.0.0.1 embedded in 64:ff9b::/96 is 64:ff9b::a00:1.
	// Reverse: 1.0.0.0.0.0.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.
	qname := "1.0.0.0.0.0.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa."

	answered := false
	downstream := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		answered = true
		ch.CancelWithRcode(dns.RcodeServerFailure, false)
	})
	ch, mw := makeChain(t, d, downstream, "203.0.113.5:53", qname, dns.TypePTR)
	d.ServeDNS(context.Background(), ch)

	assert.True(t, answered, "excluded-v4 PTR must fall through to the rest of the chain")
	assert.Equal(t, dns.RcodeServerFailure, mw.Msg().Rcode)
}

// TestPTR_OperatorPrefixTranslates confirms PTR translation works
// for an operator-chosen prefix (RFC 6147 §5.1.4 exclusion does
// not apply, so private ranges are reachable).
func TestPTR_OperatorPrefixTranslates(t *testing.T) {
	cfg := baseConfig()
	cfg.DNS64.Prefixes = []string{"2001:db8:64::/96"}
	cfg.DNS64.ExcludeANetworks = nil
	d := New(cfg)
	d.queryer = nil // confirm the CNAME-only path is also fine

	// 10.0.0.1 embedded in 2001:db8:64::/96 = 2001:db8:64::a00:1.
	// Bytes: 20 01 0d b8 00 64 00 00 00 00 00 00 0a 00 00 01.
	// 32 reverse nibbles (byte 15 low first, byte 0 high last) →
	qname := "1.0.0.0.0.0.a.0.0.0.0.0.0.0.0.0.0.0.0.0.4.6.0.0.8.b.d.0.1.0.0.2.ip6.arpa."

	ch, mw := makeChain(t, d, &stubAnswerer{}, "203.0.113.5:53", qname, dns.TypePTR)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.NotNil(t, resp) && assert.Len(t, resp.Answer, 1) {
		cname := resp.Answer[0].(*dns.CNAME)
		assert.Equal(t, "1.0.0.10.in-addr.arpa.", cname.Target)
	}
}

// TestSynthesise_DNAMEChain covers RFC 6147 §5.1.5: a DNAME in
// the A response must be carried through into the synthesised
// answer alongside any synthesised CNAME.
func TestSynthesise_DNAMEChain(t *testing.T) {
	d := New(baseConfig())
	aResp := new(dns.Msg)
	aResp.SetQuestion("alias.dept.example.org.", dns.TypeA)
	aResp.Response = true
	aResp.Rcode = dns.RcodeSuccess
	dname, _ := dns.NewRR("dept.example.org. 60 IN DNAME hosts.example.net.")
	cname, _ := dns.NewRR("alias.dept.example.org. 60 IN CNAME alias.hosts.example.net.")
	aResp.Answer = []dns.RR{
		dname,
		cname,
		&dns.A{
			Hdr: dns.RR_Header{Name: "alias.hosts.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.33"),
		},
	}
	d.queryer = &stubQueryer{resp: aResp}

	ch, mw := makeChain(t, d, &stubAnswerer{msg: noDataMsg("alias.dept.example.org.", 300)}, "203.0.113.5:53", "alias.dept.example.org.", dns.TypeAAAA)
	d.ServeDNS(context.Background(), ch)

	resp := mw.Msg()
	if assert.Len(t, resp.Answer, 3, "DNAME + synthesised CNAME + synthesised AAAA must all be present") {
		_, isDNAME := resp.Answer[0].(*dns.DNAME)
		_, isCNAME := resp.Answer[1].(*dns.CNAME)
		aaaa, isAAAA := resp.Answer[2].(*dns.AAAA)
		assert.True(t, isDNAME, "first record must be the DNAME")
		assert.True(t, isCNAME, "second record must be the synthesised CNAME")
		if assert.True(t, isAAAA) {
			assert.Equal(t, "alias.hosts.example.net.", aaaa.Hdr.Name, "synthesised AAAA owner must follow the chain to the A's terminal name")
			assert.Equal(t, "64:ff9b::c000:221", aaaa.AAAA.String())
		}
	}
}
