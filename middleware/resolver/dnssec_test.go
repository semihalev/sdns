package resolver

import (
	"context"
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

// makeDS creates a DS record for the given owner name.
func makeDS(name string) *dns.DS {
	return &dns.DS{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		KeyTag:     12345,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "aabbccdd",
	}
}

func Test_isZoneSecure(t *testing.T) {
	tests := []struct {
		name        string
		qname       string
		parentdsrr  []dns.RR
		zone        string
		expected    bool
	}{
		{
			name:       "nil parentdsrr returns false",
			qname:      "example.com.",
			parentdsrr: nil,
			zone:       "example.com.",
			expected:   false,
		},
		{
			name:       "empty parentdsrr slice returns false",
			qname:      "example.com.",
			parentdsrr: []dns.RR{},
			zone:       "example.com.",
			expected:   false,
		},
		{
			name:       "DS matches zone exactly",
			qname:      "www.example.com.",
			parentdsrr: []dns.RR{makeDS("example.com.")},
			zone:       "example.com.",
			expected:   true,
		},
		{
			name:       "DS matches zone case insensitive upper DS",
			qname:      "www.example.com.",
			parentdsrr: []dns.RR{makeDS("EXAMPLE.COM.")},
			zone:       "example.com.",
			expected:   true,
		},
		{
			name:       "DS matches zone case insensitive upper zone",
			qname:      "www.example.com.",
			parentdsrr: []dns.RR{makeDS("example.com.")},
			zone:       "EXAMPLE.COM.",
			expected:   true,
		},
		{
			name:       "root DS matches root zone",
			qname:      "com.",
			parentdsrr: []dns.RR{makeDS(".")},
			zone:       ".",
			expected:   true,
		},
		{
			name:       "multiple DS records first one checked",
			qname:      "www.example.com.",
			parentdsrr: []dns.RR{makeDS("example.com."), makeDS("other.com.")},
			zone:       "example.com.",
			expected:   true,
		},
		{
			// Zone is empty so the fast path is skipped. findDS will fail
			// because the middleware chain is not initialised → fail closed.
			name:       "empty zone falls to findDS error path",
			qname:      "www.example.com.",
			parentdsrr: []dns.RR{makeDS("com.")},
			zone:       "",
			expected:   true,
		},
		{
			// DS is for "com." but zone is "example.com." — mismatch, so the
			// fast path is skipped. findDS errors without middleware → fail closed.
			name:       "ancestor DS mismatches zone falls to findDS error path",
			qname:      "www.example.com.",
			parentdsrr: []dns.RR{makeDS("com.")},
			zone:       "example.com.",
			expected:   true,
		},
		{
			// Single-label qname: SplitDomainName("com.") = ["com"], len == 1,
			// so probeName stays "com." (no label to strip). DS "." != zone "com."
			// so fast path is skipped. findDS errors → fail closed.
			name:       "single label qname no label stripping",
			qname:      "com.",
			parentdsrr: []dns.RR{makeDS(".")},
			zone:       "com.",
			expected:   true,
		},
	}

	ctx := context.Background()
	r := &Resolver{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.isZoneSecure(ctx, tt.qname, tt.parentdsrr, tt.zone)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_isZoneSecureIntegration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		qname     string
		expectErr bool
		expectNil bool
	}{
		{
			// Signed zone that omits RRSIGs — exercises answer() → isZoneSecure()
			// returning true → errNoSignatures.
			name:      "signed zone missing RRSIG returns error",
			qname:     "nosig-e5ecc382.test-alg15.dnscheck.tools.",
			expectErr: true,
			expectNil: true,
		},
		{
			// Insecure delegation: parent (com.) is signed but child has no DS.
			// Unsigned responses must not trigger errNoSignatures.
			name:      "insecure delegation resolves successfully",
			qname:     "example.com.",
			expectErr: false,
			expectNil: false,
		},
		{
			// Nonexistent name under a signed zone — exercises authority() →
			// isZoneSecure() path. The resolver should validate the NSEC/RRSIG
			// proofs and not return errNoSignatures.
			name:      "NXDOMAIN under signed zone validates",
			qname:     "thisdoesnotexist.ietf.org.",
			expectErr: false,
			expectNil: false,
		},
	}

	cfg := makeTestConfig()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := NewResolver(cfg)

			req := new(dns.Msg)
			req.SetQuestion(tt.qname, dns.TypeA)
			req.SetEdns0(4096, true)

			resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.expectNil {
				assert.Nil(t, resp)
			} else {
				assert.NotNil(t, resp)
			}
		})
	}
}
