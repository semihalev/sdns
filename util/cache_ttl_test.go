package util

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestCalculateCacheTTLWithRRSIG(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		msg         *dns.Msg
		respType    ResponseType
		expectedTTL time.Duration
	}{
		{
			name: "RRSIG expires before record TTL",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    3600, // 1 hour
						},
						A: []byte{192, 0, 2, 1},
					},
					&dns.RRSIG{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeRRSIG,
							Class:  dns.ClassINET,
							Ttl:    3600, // 1 hour
						},
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(10 * time.Minute).Unix()), // Expires in 10 minutes
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
					},
				},
			},
			respType:    TypeSuccess,
			expectedTTL: 10 * time.Minute, // Should use RRSIG expiration
		},
		{
			name: "Record TTL expires before RRSIG",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300, // 5 minutes
						},
						A: []byte{192, 0, 2, 1},
					},
					&dns.RRSIG{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeRRSIG,
							Class:  dns.ClassINET,
							Ttl:    300, // 5 minutes
						},
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(2 * time.Hour).Unix()), // Expires in 2 hours
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
					},
				},
			},
			respType:    TypeSuccess,
			expectedTTL: 5 * time.Minute, // Should use record TTL
		},
		{
			name: "Expired RRSIG",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						A: []byte{192, 0, 2, 1},
					},
					&dns.RRSIG{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeRRSIG,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(-1 * time.Hour).Unix()), // Already expired
						Inception:   uint32(now.Add(-2 * time.Hour).Unix()),
					},
				},
			},
			respType:    TypeSuccess,
			expectedTTL: MinCacheTTL, // Should use minimum TTL
		},
		{
			name: "Multiple RRSIGs with different expirations",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						A: []byte{192, 0, 2, 1},
					},
					&dns.RRSIG{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeRRSIG,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						TypeCovered: dns.TypeA,
						Algorithm:   dns.RSASHA256,
						Expiration:  uint32(now.Add(30 * time.Minute).Unix()),
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
					},
					&dns.RRSIG{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeRRSIG,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						TypeCovered: dns.TypeA,
						Algorithm:   dns.ECDSAP256SHA256,
						Expiration:  uint32(now.Add(15 * time.Minute).Unix()), // Expires sooner
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
					},
				},
			},
			respType:    TypeSuccess,
			expectedTTL: 15 * time.Minute, // Should use earliest expiration
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl := CalculateCacheTTL(tt.msg, tt.respType)

			// Allow small time difference due to execution time
			delta := time.Second
			assert.InDelta(t, tt.expectedTTL.Seconds(), ttl.Seconds(), delta.Seconds(),
				"TTL should be approximately %v but got %v", tt.expectedTTL, ttl)
		})
	}
}

func TestGetRRSIGTTL(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		sig         *dns.RRSIG
		expectedTTL time.Duration
	}{
		{
			name: "Signature expires in 1 hour, TTL is 2 hours",
			sig: &dns.RRSIG{
				Hdr: dns.RR_Header{
					Ttl: 7200, // 2 hours
				},
				Expiration: uint32(now.Add(1 * time.Hour).Unix()),
			},
			expectedTTL: 1 * time.Hour,
		},
		{
			name: "Signature expires in 2 hours, TTL is 1 hour",
			sig: &dns.RRSIG{
				Hdr: dns.RR_Header{
					Ttl: 3600, // 1 hour
				},
				Expiration: uint32(now.Add(2 * time.Hour).Unix()),
			},
			expectedTTL: 1 * time.Hour,
		},
		{
			name: "Signature already expired",
			sig: &dns.RRSIG{
				Hdr: dns.RR_Header{
					Ttl: 3600,
				},
				Expiration: uint32(now.Add(-1 * time.Hour).Unix()),
			},
			expectedTTL: MinCacheTTL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl := getRRSIGTTL(tt.sig, now)

			// Allow small time difference due to execution time
			delta := time.Second
			assert.InDelta(t, tt.expectedTTL.Seconds(), ttl.Seconds(), delta.Seconds(),
				"TTL should be approximately %v but got %v", tt.expectedTTL, ttl)
		})
	}
}
