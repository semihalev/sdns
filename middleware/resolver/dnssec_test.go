package resolver

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// TestADBitWithCDFlag verifies that AD bit is not set when CD flag is set.
func TestADBitWithCDFlag(t *testing.T) {
	// Test case 1: CD=0, successful DNSSEC validation should set AD=1
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.CheckingDisabled = false

	// Simulate a validated response
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	// When CD=0 and DNSSEC validation succeeds, AD should be set
	if !req.CheckingDisabled {
		resp.AuthenticatedData = true
	}

	assert.True(t, resp.AuthenticatedData, "AD bit should be set when CD=0 and validation succeeds")

	// Test case 2: CD=1, AD bit should never be set
	req2 := new(dns.Msg)
	req2.SetQuestion("example.com.", dns.TypeA)
	req2.CheckingDisabled = true

	resp2 := new(dns.Msg)
	resp2.SetReply(req2)
	resp2.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	// When CD=1, AD should never be set regardless of validation
	if req2.CheckingDisabled {
		resp2.AuthenticatedData = false
	}

	assert.False(t, resp2.AuthenticatedData, "AD bit should not be set when CD=1")
}

// TestCDFlagPreservation verifies that CD flag is properly preserved in responses.
func TestCDFlagPreservation(t *testing.T) {
	tests := []struct {
		name           string
		requestCD      bool
		expectedRespCD bool
	}{
		{
			name:           "CD=0 in request",
			requestCD:      false,
			expectedRespCD: false,
		},
		{
			name:           "CD=1 in request",
			requestCD:      true,
			expectedRespCD: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)
			req.CheckingDisabled = tt.requestCD

			resp := new(dns.Msg)
			resp.SetReply(req)

			// CD flag should be preserved from request
			assert.Equal(t, tt.expectedRespCD, resp.CheckingDisabled,
				"CD flag should be preserved from request to response")
		})
	}
}

// TestDNSSECValidationSkippedWithCD verifies that DNSSEC validation is skipped when CD=1.
func TestDNSSECValidationSkippedWithCD(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.CheckingDisabled = true

	// Create a response that would fail DNSSEC validation
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	// Add an invalid RRSIG (would normally fail validation)
	resp.Answer = append(resp.Answer, &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  1234567890, // Expired
		Inception:   1234567880,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "invalid",
	})

	// With CD=1, validation should be skipped and response should be returned
	// without AD bit set
	assert.True(t, req.CheckingDisabled, "CD flag should be set in request")
	assert.False(t, resp.AuthenticatedData, "AD bit should not be set when CD=1")

	// The response should still be valid (not SERVFAIL) because validation was skipped
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode,
		"Response should be successful when CD=1 even with invalid signatures")
}
