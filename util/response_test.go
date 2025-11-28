package util

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestClassifyResponse(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		msg          *dns.Msg
		expectedType ResponseType
		hasOpt       bool
	}{
		{
			name: "Success with answers",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Rcode = dns.RcodeSuccess
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{192, 0, 2, 1},
					},
				}
				return m
			}(),
			expectedType: TypeSuccess,
			hasOpt:       false,
		},
		{
			name: "Success with answers and EDNS0",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Rcode = dns.RcodeSuccess
				m.SetEdns0(4096, true)
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{192, 0, 2, 1},
					},
				}
				return m
			}(),
			expectedType: TypeSuccess,
			hasOpt:       true,
		},
		{
			name: "NXDOMAIN",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("nonexistent.example.com.", dns.TypeA)
				m.Rcode = dns.RcodeNameError
				return m
			}(),
			expectedType: TypeNXDomain,
			hasOpt:       false,
		},
		{
			name: "SERVFAIL",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Rcode = dns.RcodeServerFailure
				return m
			}(),
			expectedType: TypeServerFailure,
			hasOpt:       false,
		},
		{
			name: "NODATA with SOA",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeAAAA)
				m.Rcode = dns.RcodeSuccess
				m.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
					},
				}
				return m
			}(),
			expectedType: TypeNoRecords,
			hasOpt:       false,
		},
		{
			name: "Referral/Delegation",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("sub.example.com.", dns.TypeA)
				m.Rcode = dns.RcodeSuccess
				m.Ns = []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
						Ns:  "ns1.sub.example.com.",
					},
				}
				return m
			}(),
			expectedType: TypeReferral,
			hasOpt:       false,
		},
		{
			name: "AXFR query",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeAXFR)
				m.Rcode = dns.RcodeSuccess
				return m
			}(),
			expectedType: TypeMetaQuery,
			hasOpt:       false,
		},
		{
			name: "IXFR query",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeIXFR)
				m.Rcode = dns.RcodeSuccess
				return m
			}(),
			expectedType: TypeMetaQuery,
			hasOpt:       false,
		},
		{
			name: "Dynamic update",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeSOA)
				m.Opcode = dns.OpcodeUpdate
				m.Rcode = dns.RcodeSuccess
				return m
			}(),
			expectedType: TypeDynamicUpdate,
			hasOpt:       false,
		},
		{
			name: "Notify",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeSOA)
				m.Opcode = dns.OpcodeNotify
				m.Rcode = dns.RcodeSuccess
				return m
			}(),
			expectedType: TypeMetaQuery,
			hasOpt:       false,
		},
		{
			name: "Expired RRSIG in answer",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Rcode = dns.RcodeSuccess
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{192, 0, 2, 1},
					},
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec
						Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec
					},
				}
				return m
			}(),
			expectedType: TypeExpiredSignature,
			hasOpt:       false,
		},
		{
			name: "DNSKEY query with empty answer - not cacheable",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeDNSKEY)
				m.Rcode = dns.RcodeSuccess
				return m
			}(),
			expectedType: TypeNotCacheable,
			hasOpt:       false,
		},
		{
			name: "Other error rcode",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Rcode = dns.RcodeRefused
				return m
			}(),
			expectedType: TypeServerFailure,
			hasOpt:       false,
		},
		{
			name: "Success with no answers and no NS/SOA - cacheable query type",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Rcode = dns.RcodeSuccess
				return m
			}(),
			expectedType: TypeSuccess, // A query is cacheable even without answers
			hasOpt:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			respType, opt := ClassifyResponse(tt.msg, now)

			assert.Equal(t, tt.expectedType, respType)
			if tt.hasOpt {
				assert.NotNil(t, opt)
			} else {
				assert.Nil(t, opt)
			}
		})
	}
}

func TestIsDelegation(t *testing.T) {
	tests := []struct {
		name     string
		msg      *dns.Msg
		expected bool
	}{
		{
			name: "Delegation with NS record",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("sub.example.com.", dns.TypeA)
				m.Ns = []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
						Ns:  "ns1.sub.example.com.",
					},
				}
				return m
			}(),
			expected: true,
		},
		{
			name: "No delegation - no NS records",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
					},
				}
				return m
			}(),
			expected: false,
		},
		{
			name: "Empty question",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				return m
			}(),
			expected: false,
		},
		{
			name: "Empty authority section",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDelegation(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasSOA(t *testing.T) {
	tests := []struct {
		name     string
		msg      *dns.Msg
		expected bool
	}{
		{
			name: "Has SOA in authority",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
					},
				}
				return m
			}(),
			expected: true,
		},
		{
			name: "No SOA in authority",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Ns = []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
						Ns:  "ns1.example.com.",
					},
				}
				return m
			}(),
			expected: false,
		},
		{
			name: "Empty authority section",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				return m
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasSOA(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasExpiredSignatures(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		msg      *dns.Msg
		expected bool
	}{
		{
			name: "Expired RRSIG in answer",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Answer = []dns.RR{
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec
						Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec
					},
				}
				return m
			}(),
			expected: true,
		},
		{
			name: "Expired RRSIG in authority",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Ns = []dns.RR{
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeSOA,
						Expiration:  uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec
						Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec
					},
				}
				return m
			}(),
			expected: true,
		},
		{
			name: "Expired RRSIG in extra",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Extra = []dns.RR{
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec
						Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec
					},
				}
				return m
			}(),
			expected: true,
		},
		{
			name: "Valid RRSIG",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Answer = []dns.RR{
					&dns.RRSIG{
						Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(1 * time.Hour).Unix()), //nolint:gosec
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec
					},
				}
				return m
			}(),
			expected: false,
		},
		{
			name: "No RRSIG records",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   []byte{192, 0, 2, 1},
					},
				}
				return m
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasExpiredSignatures(tt.msg, now)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldCache(t *testing.T) {
	tests := []struct {
		name     string
		msg      *dns.Msg
		expected bool
	}{
		{
			name: "A query - should cache",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			expected: true,
		},
		{
			name: "AAAA query - should cache",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeAAAA)
				return m
			}(),
			expected: true,
		},
		{
			name: "DNSKEY query - should not cache",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeDNSKEY)
				return m
			}(),
			expected: false,
		},
		{
			name: "Empty question - should not cache",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				return m
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldCache(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}
}
