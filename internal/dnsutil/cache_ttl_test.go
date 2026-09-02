package dnsutil

import (
	"math"
	"testing"
	"time"

	"github.com/miekg/dns"
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
						OrigTtl:     3600,
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(10 * time.Minute).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()),   //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
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
						OrigTtl:     300,
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(2 * time.Hour).Unix()),  //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
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
						OrigTtl:     3600,
						TypeCovered: dns.TypeA,
						Expiration:  uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
						Inception:   uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
					},
				},
			},
			respType: TypeSuccess,
			// Zero, not the floor. A lapsed signature is a bound the protocol
			// fixes (RFC 4035 §5.3.3), and the cache's own minimum is not
			// entitled to lift an answer past it. The floor used to win here
			// and bought the expired data another five seconds. In the running
			// server this shape never arrives as a success anyway,
			// ClassifyResponse names it TypeExpiredSignature first.
			expectedTTL: 0,
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
						OrigTtl:     3600,
						TypeCovered: dns.TypeA,
						Algorithm:   dns.RSASHA256,
						Expiration:  uint32(now.Add(30 * time.Minute).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()),   //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
					},
					&dns.RRSIG{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeRRSIG,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
						OrigTtl:     3600,
						TypeCovered: dns.TypeA,
						Algorithm:   dns.ECDSAP256SHA256,
						Expiration:  uint32(now.Add(15 * time.Minute).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
						Inception:   uint32(now.Add(-1 * time.Hour).Unix()),   //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
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
			if math.Abs(ttl.Seconds()-tt.expectedTTL.Seconds()) > delta.Seconds() {
				t.Errorf("TTL should be approximately %v but got %v", tt.expectedTTL, ttl)
			}
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
				OrigTtl:    7200,
				Expiration: uint32(now.Add(1 * time.Hour).Unix()), //nolint:gosec // G115 - Unix timestamp fits in uint32 for valid dates
			},
			expectedTTL: 1 * time.Hour,
		},
		{
			name: "Signature expires in 2 hours, TTL is 1 hour",
			sig: &dns.RRSIG{
				Hdr: dns.RR_Header{
					Ttl: 3600, // 1 hour
				},
				OrigTtl:    3600,
				Expiration: uint32(now.Add(2 * time.Hour).Unix()), //nolint:gosec // G115 - Unix timestamp
			},
			expectedTTL: 1 * time.Hour,
		},
		{
			// Zero, not the floor. This function reports a bound, and a
			// lapsed signature bounds the data at nothing; the floor is
			// applied afterwards and only to the response types that take
			// one. Returning MinCacheTTL here used to be the last thing
			// granting a denial five more seconds on an expired proof.
			name: "Signature already expired",
			sig: &dns.RRSIG{
				Hdr: dns.RR_Header{
					Ttl: 3600,
				},
				OrigTtl:    3600,
				Expiration: uint32(now.Add(-1 * time.Hour).Unix()), //nolint:gosec // G115 - Unix timestamp
			},
			expectedTTL: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl := getRRSIGTTL(tt.sig, now)

			// Allow small time difference due to execution time
			delta := time.Second
			if math.Abs(ttl.Seconds()-tt.expectedTTL.Seconds()) > delta.Seconds() {
				t.Errorf("TTL should be approximately %v but got %v", tt.expectedTTL, ttl)
			}
		})
	}
}
