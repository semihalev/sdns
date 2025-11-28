package util

import (
	"encoding/base64"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func TestSetEdns0(t *testing.T) {
	tests := []struct {
		name             string
		req              *dns.Msg
		expectedSize     int
		expectedCookie   string
		expectedNsid     bool
		expectedOrigDo   bool // Original DO bit from request
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
			opt, size, cookie, nsid, origDo := SetEdns0(tt.req)

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

func TestParsePurgeQuestion(t *testing.T) {
	tests := []struct {
		name          string
		req           *dns.Msg
		expectedQname string
		expectedQtype uint16
		expectedOk    bool
	}{
		{
			name: "Valid A record purge",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				encoded := base64.StdEncoding.EncodeToString([]byte("A:example.com"))
				m.SetQuestion(encoded+".", dns.TypeNULL)
				return m
			}(),
			expectedQname: "example.com",
			expectedQtype: dns.TypeA,
			expectedOk:    true,
		},
		{
			name: "Valid AAAA record purge",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				encoded := base64.StdEncoding.EncodeToString([]byte("AAAA:example.com"))
				m.SetQuestion(encoded+".", dns.TypeNULL)
				return m
			}(),
			expectedQname: "example.com",
			expectedQtype: dns.TypeAAAA,
			expectedOk:    true,
		},
		{
			name: "Invalid base64",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("!!!invalid!!!.", dns.TypeNULL)
				return m
			}(),
			expectedQname: "",
			expectedQtype: 0,
			expectedOk:    false,
		},
		{
			name: "Invalid format (no colon)",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				encoded := base64.StdEncoding.EncodeToString([]byte("Aexample.com"))
				m.SetQuestion(encoded+".", dns.TypeNULL)
				return m
			}(),
			expectedQname: "",
			expectedQtype: 0,
			expectedOk:    false,
		},
		{
			name: "Invalid record type",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				encoded := base64.StdEncoding.EncodeToString([]byte("INVALID:example.com"))
				m.SetQuestion(encoded+".", dns.TypeNULL)
				return m
			}(),
			expectedQname: "",
			expectedQtype: 0,
			expectedOk:    false,
		},
		{
			name: "Empty question",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				return m
			}(),
			expectedQname: "",
			expectedQtype: 0,
			expectedOk:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qname, qtype, ok := ParsePurgeQuestion(tt.req)

			assert.Equal(t, tt.expectedOk, ok)
			if ok {
				assert.Equal(t, tt.expectedQname, qname)
				assert.Equal(t, tt.expectedQtype, qtype)
			}
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
