package dnsutil

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/ecs"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestSetEdns0(t *testing.T) {
	tests := []struct {
		name           string
		req            *dns.Msg
		expectedSize   int
		expectedCookie string
		expectedNsid   bool
		expectedOrigDo bool // Original DO bit from request
	}{
		{
			name: "Request without EDNS0",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			expectedSize:   DefaultMsgSize,
			expectedCookie: "",
			expectedNsid:   false,
			expectedOrigDo: false, // No EDNS0 = no DO bit
		},
		{
			name: "Request with EDNS0 and DO bit",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, true)
				return m
			}(),
			expectedSize:   DefaultMsgSize,
			expectedCookie: "",
			expectedNsid:   false,
			expectedOrigDo: true, // DO bit was set
		},
		{
			name: "Request with small UDP size",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(256, false)
				return m
			}(),
			expectedSize:   dns.MinMsgSize,
			expectedCookie: "",
			expectedNsid:   false,
			expectedOrigDo: false, // DO bit not set
		},
		{
			name: "Request with large UDP size",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, false)
				return m
			}(),
			expectedSize:   DefaultMsgSize,
			expectedCookie: "",
			expectedNsid:   false,
			expectedOrigDo: false, // DO bit not set
		},
		{
			name: "Request with cookie",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetUDPSize(DefaultMsgSize)
				cookie := &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "1234567890abcdef"}
				opt.Option = append(opt.Option, cookie)
				m.Extra = append(m.Extra, opt)
				return m
			}(),
			expectedSize:   DefaultMsgSize,
			expectedCookie: "1234567890abcdef",
			expectedNsid:   false,
			expectedOrigDo: false,
		},
		{
			name: "Request with NSID",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetUDPSize(DefaultMsgSize)
				nsid := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}
				opt.Option = append(opt.Option, nsid)
				m.Extra = append(m.Extra, opt)
				return m
			}(),
			expectedSize:   DefaultMsgSize,
			expectedCookie: "",
			expectedNsid:   true,
			expectedOrigDo: false,
		},
		{
			name: "Request with ECS (should be stripped)",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetUDPSize(DefaultMsgSize)
				ecs := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: []byte{192, 168, 1, 0}}
				opt.Option = append(opt.Option, ecs)
				m.Extra = append(m.Extra, opt)
				return m
			}(),
			expectedSize:   DefaultMsgSize,
			expectedCookie: "",
			expectedNsid:   false,
			expectedOrigDo: false,
		},
		{
			name: "Request with EDNS version != 0",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetUDPSize(DefaultMsgSize)
				opt.SetVersion(1) // BADVERS
				m.Extra = append(m.Extra, opt)
				return m
			}(),
			expectedSize:   DefaultMsgSize,
			expectedCookie: "",
			expectedNsid:   false,
			expectedOrigDo: false, // Returns false for bad version
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Nil policy + zero addr exercises the default-strip path,
			// matching the pre-7871 contract this test was written for.
			opt, size, cookie, nsid, origDo := SetEdns0(tt.req, nil, netip.Addr{})

			assert.NotNil(t, opt)
			assert.Equal(t, tt.expectedSize, size)
			assert.Equal(t, tt.expectedCookie, cookie)
			assert.Equal(t, tt.expectedNsid, nsid)
			assert.Equal(t, tt.expectedOrigDo, origDo)

			// Verify OPT record is now in request
			reqOpt := tt.req.IsEdns0()
			assert.NotNil(t, reqOpt)
		})
	}
}

// reqWithECS builds a query whose OPT carries one EDNS0_SUBNET.
func reqWithECS(family uint16, src uint8, addr string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	parsed := net.ParseIP(addr)
	if family == 1 {
		parsed = parsed.To4()
	}
	opt.Option = []dns.EDNS0{&dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: family,
		SourceNetmask: src, SourceScope: 0,
		Address: parsed,
	}}
	req.Extra = []dns.RR{opt}
	return req
}

// findECS returns the first EDNS0_SUBNET option on opt, or nil.
func findECS(opt *dns.OPT) *dns.EDNS0_SUBNET {
	for _, o := range opt.Option {
		if v, ok := o.(*dns.EDNS0_SUBNET); ok {
			return v
		}
	}
	return nil
}

func TestSetEdns0_StripsECSByDefault(t *testing.T) {
	// Regression: the historical contract (RFC 7871 §11) is to strip
	// every option. Nil policy must keep that behaviour.
	req := reqWithECS(1, 32, "203.0.113.5")
	opt, _, _, _, _ := SetEdns0(req, nil, netip.Addr{})
	if got := findECS(opt); got != nil {
		t.Errorf("nil policy should strip ECS, got %+v", got)
	}
}

func TestSetEdns0_StripsECSWhenPolicyDisabled(t *testing.T) {
	req := reqWithECS(1, 24, "203.0.113.0")
	policy := &ecs.Policy{Enabled: false, ForwardV4Max: 24}
	client := netip.MustParseAddr("203.0.113.5")
	opt, _, _, _, _ := SetEdns0(req, policy, client)
	if got := findECS(opt); got != nil {
		t.Errorf("disabled policy should strip ECS, got %+v", got)
	}
}

func TestSetEdns0_ForwardsECSClampedToCeiling(t *testing.T) {
	// Client sent /28 (too narrow); policy ceiling is /24. The
	// outgoing OPT must carry a /24 with the host bits zeroed.
	req := reqWithECS(1, 28, "203.0.113.42")
	policy := &ecs.Policy{Enabled: true, ForwardV4Max: 24}
	client := netip.MustParseAddr("203.0.113.42")
	opt, _, _, _, _ := SetEdns0(req, policy, client)
	got := findECS(opt)
	if got == nil {
		t.Fatal("expected ECS to be forwarded")
	}
	if got.SourceNetmask != 24 {
		t.Errorf("source netmask = %d, want 24", got.SourceNetmask)
	}
	if got.Address.String() != "203.0.113.0" {
		t.Errorf("address = %s, want 203.0.113.0 (truncated)", got.Address)
	}
	if got.SourceScope != 0 {
		t.Errorf("outgoing scope must be 0, got %d", got.SourceScope)
	}
}

func TestSetEdns0_DropsECSWhenClientNotInAllowList(t *testing.T) {
	req := reqWithECS(1, 24, "203.0.113.0")
	policy := &ecs.Policy{
		Enabled:        true,
		ForwardV4Max:   24,
		ClientNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	client := netip.MustParseAddr("203.0.113.5") // outside the allow-list
	opt, _, _, _, _ := SetEdns0(req, policy, client)
	if got := findECS(opt); got != nil {
		t.Errorf("client outside allow-list should not get ECS forwarded, got %+v", got)
	}
}

func TestSetEdns0_NoECSInRequestNoForwarding(t *testing.T) {
	// Client didn't send ECS at all — Stage 1 is forward-only,
	// not synthesise, so the outgoing OPT must have no ECS option.
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	req.Extra = []dns.RR{opt}

	policy := &ecs.Policy{Enabled: true, ForwardV4Max: 24}
	client := netip.MustParseAddr("203.0.113.5")
	out, _, _, _, _ := SetEdns0(req, policy, client)
	if got := findECS(out); got != nil {
		t.Errorf("no client ECS should mean no forwarded ECS, got %+v", got)
	}
}

func TestGenerateServerCookie(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		remoteip string
		cookie   string
	}{
		{
			name:     "Basic cookie generation",
			secret:   "mysecret",
			remoteip: "192.168.1.1",
			cookie:   "1234567890abcdef",
		},
		{
			name:     "Different remote IP",
			secret:   "mysecret",
			remoteip: "10.0.0.1",
			cookie:   "1234567890abcdef",
		},
		{
			name:     "Different secret",
			secret:   "anothersecret",
			remoteip: "192.168.1.1",
			cookie:   "1234567890abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateServerCookie(tt.secret, tt.remoteip, tt.cookie)

			// Cookie should start with the original cookie
			assert.True(t, len(result) > len(tt.cookie))
			assert.Equal(t, tt.cookie, result[:len(tt.cookie)])

			// Generate same cookie with same parameters should be identical
			result2 := GenerateServerCookie(tt.secret, tt.remoteip, tt.cookie)
			assert.Equal(t, result, result2)

			// Different parameters should produce different results
			result3 := GenerateServerCookie(tt.secret+"x", tt.remoteip, tt.cookie)
			assert.NotEqual(t, result, result3)
		})
	}
}

func TestClearOPT(t *testing.T) {
	tests := []struct {
		name          string
		msg           *dns.Msg
		expectedExtra int
	}{
		{
			name: "Message with only OPT record",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, true)
				return m
			}(),
			expectedExtra: 0,
		},
		{
			name: "Message without OPT record",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			expectedExtra: 0,
		},
		{
			name: "Message with OPT and other records",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, true)
				m.Extra = append(m.Extra, &dns.A{
					Hdr: dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
					A:   []byte{192, 0, 2, 1},
				})
				return m
			}(),
			expectedExtra: 1, // Only A record should remain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClearOPT(tt.msg)

			assert.Equal(t, tt.expectedExtra, len(result.Extra))
			// Verify no OPT records remain
			assert.Nil(t, result.IsEdns0())
		})
	}
}

func TestClearDNSSEC(t *testing.T) {
	tests := []struct {
		name           string
		msg            *dns.Msg
		expectedAnswer int
		expectedNs     int
	}{
		{
			name: "Message with RRSIG in answer",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{192, 0, 2, 1},
					},
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeA,
					},
				}
				return m
			}(),
			expectedAnswer: 1,
			expectedNs:     0,
		},
		{
			name: "Message with NSEC in authority",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
					},
					&dns.NSEC{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
					},
				}
				return m
			}(),
			expectedAnswer: 0,
			expectedNs:     1,
		},
		{
			name: "Message with NSEC3 in authority",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
					},
					&dns.NSEC3{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
					},
				}
				return m
			}(),
			expectedAnswer: 0,
			expectedNs:     1,
		},
		{
			name: "RRSIG query should not be cleared",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeRRSIG)
				m.Answer = []dns.RR{
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeA,
					},
				}
				return m
			}(),
			expectedAnswer: 1, // RRSIG should remain because it's an RRSIG query
			expectedNs:     0,
		},
		{
			name: "Message without DNSSEC records",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{192, 0, 2, 1},
					},
				}
				return m
			}(),
			expectedAnswer: 1,
			expectedNs:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClearDNSSEC(tt.msg)

			assert.Equal(t, tt.expectedAnswer, len(result.Answer))
			assert.Equal(t, tt.expectedNs, len(result.Ns))
		})
	}
}

func TestNotSupported(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 12345
	req.Opcode = dns.OpcodeQuery

	w := mock.NewWriter("tcp", "127.0.0.1:0")

	err := NotSupported(w, req)
	assert.NoError(t, err)

	msg := w.Msg()
	assert.NotNil(t, msg)
	assert.Equal(t, dns.RcodeNotImplemented, msg.Rcode)
	assert.Equal(t, req.Id, msg.Id)
	assert.True(t, msg.Response)
	assert.True(t, msg.RecursionDesired)
	assert.True(t, msg.AuthenticatedData)
}

func TestSetRcode(t *testing.T) {
	tests := []struct {
		name         string
		rcode        int
		do           bool
		expectedDo   bool
		expectedRc   int
		expectedEdns bool
	}{
		{
			name:         "SERVFAIL with DO",
			rcode:        dns.RcodeServerFailure,
			do:           true,
			expectedDo:   true,
			expectedRc:   dns.RcodeServerFailure,
			expectedEdns: true,
		},
		{
			name:         "NXDOMAIN without DO",
			rcode:        dns.RcodeNameError,
			do:           false,
			expectedDo:   false,
			expectedRc:   dns.RcodeNameError,
			expectedEdns: true,
		},
		{
			name:         "NOERROR with DO",
			rcode:        dns.RcodeSuccess,
			do:           true,
			expectedDo:   true,
			expectedRc:   dns.RcodeSuccess,
			expectedEdns: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)
			req.SetEdns0(4096, false)

			msg := SetRcode(req, tt.rcode, tt.do)

			assert.Equal(t, tt.expectedRc, msg.Rcode)
			assert.True(t, msg.RecursionAvailable)
			assert.True(t, msg.RecursionDesired)

			opt := msg.IsEdns0()
			if tt.expectedEdns {
				assert.NotNil(t, opt)
				assert.Equal(t, tt.expectedDo, opt.Do())
			}
		})
	}
}
