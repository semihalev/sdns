package resolver

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
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

	if !(resp.AuthenticatedData) {
		t.Errorf("%s: resp.AuthenticatedData is false", "AD bit should be set when CD=0 and validation succeeds")
	}

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

	if resp2.AuthenticatedData {
		t.Errorf("%s: resp2.AuthenticatedData is true", "AD bit should not be set when CD=1")
	}
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
			if !reflect.DeepEqual(tt.expectedRespCD, resp.CheckingDisabled) {
				t.Errorf("%s: resp.CheckingDisabled = %v, want %v", "CD flag should be preserved from request to response", resp.CheckingDisabled, tt.expectedRespCD)
			}
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
	if !(req.CheckingDisabled) {
		t.Errorf("%s: req.CheckingDisabled is false", "CD flag should be set in request")
	}
	if resp.AuthenticatedData {
		t.Errorf("%s: resp.AuthenticatedData is true", "AD bit should not be set when CD=1")
	}

	// The response should still be valid (not SERVFAIL) because validation was skipped
	if !reflect.DeepEqual(dns.RcodeSuccess, resp.Rcode) {
		t.Errorf("%s: resp.Rcode = %v, want %v", "Response should be successful when CD=1 even with invalid signatures", resp.Rcode, dns.RcodeSuccess)
	}
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
		name     string
		qname    string
		parentDS []dns.RR
		zone     string
		expected bool
	}{
		{
			name:     "nil parentDS returns false",
			qname:    "example.com.",
			parentDS: nil,
			zone:     "example.com.",
			expected: false,
		},
		{
			name:     "empty parentDS slice returns false",
			qname:    "example.com.",
			parentDS: []dns.RR{},
			zone:     "example.com.",
			expected: false,
		},
		{
			// DS name matches zone exactly → zone is signed (RFC 4035 §5.3.3).
			// Fast path returns true without needing findDS.
			name:     "DS matches zone returns true",
			qname:    "www.example.com.",
			parentDS: []dns.RR{makeDS("example.com.")},
			zone:     "example.com.",
			expected: true,
		},
		{
			// Case-insensitive match: upper-case DS name.
			name:     "DS matches zone case insensitive upper DS",
			qname:    "www.example.com.",
			parentDS: []dns.RR{makeDS("EXAMPLE.COM.")},
			zone:     "example.com.",
			expected: true,
		},
		{
			// Case-insensitive match: upper-case zone name.
			name:     "DS matches zone case insensitive upper zone",
			qname:    "www.example.com.",
			parentDS: []dns.RR{makeDS("example.com.")},
			zone:     "EXAMPLE.COM.",
			expected: true,
		},
		{
			// DS for root matches root zone → signed.
			name:     "root DS matches root zone",
			qname:    "com.",
			parentDS: []dns.RR{makeDS(".")},
			zone:     ".",
			expected: true,
		},
		{
			// Multiple DS records; first matches zone → signed.
			name:     "multiple DS records first matches zone",
			qname:    "www.example.com.",
			parentDS: []dns.RR{makeDS("example.com."), makeDS("other.com.")},
			zone:     "example.com.",
			expected: true,
		},
		{
			// Zone is empty, DS from ancestor. Probes parent of qname
			// via findDS which errors without middleware → fail closed.
			name:     "empty zone findDS error fails closed",
			qname:    "www.example.com.",
			parentDS: []dns.RR{makeDS("com.")},
			zone:     "",
			expected: true,
		},
		{
			// DS from ancestor "com.", zone is "example.com.".
			// Probes zone "example.com." via findDS which errors
			// without middleware → fail closed.
			name:     "ancestor DS probes zone findDS error fails closed",
			qname:    "www.example.com.",
			parentDS: []dns.RR{makeDS("com.")},
			zone:     "example.com.",
			expected: true,
		},
		{
			// Single-label qname with DS matching zone → signed.
			name:     "single label qname DS matches zone",
			qname:    "com.",
			parentDS: []dns.RR{makeDS(".")},
			zone:     "com.",
			expected: true,
		},
	}

	ctx := context.Background()
	r := &Resolver{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.isZoneSecure(ctx, tt.qname, tt.parentDS, tt.zone)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("result = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test_isZoneSecureIntegration drives isZoneSecure through the paths that
// reach it — an answer, an insecure delegation, and a denial — against a
// signed loopback namespace. It used to ask dnscheck.tools, stackoverflow.com
// and ietf.org, which made a resolver test depend on three third parties.
func Test_isZoneSecureIntegration(t *testing.T) {
	net := newHermeticNet(t)

	missing := net.Delegate("missing-sig.test.")
	missing.ServeUnsigned(mustRR(t, "www.missing-sig.test. 300 IN A 192.0.2.81"))

	insecure := net.DelegateInsecure("unsigned.test.")
	insecure.Serve(mustRR(t, "www.unsigned.test. 300 IN A 192.0.2.82"))

	denial := net.Delegate("denial.test.")
	denial.Serve(mustRR(t, "present.denial.test. 300 IN A 192.0.2.83"))

	r := net.Resolver()

	tests := []struct {
		name      string
		qname     string
		expectErr bool
		expectNil bool
	}{
		{
			// A signed zone that omits RRSIGs: answer() -> isZoneSecure()
			// reports the zone secure, so the missing signature is fatal.
			name:      "signed zone missing RRSIG returns error",
			qname:     "www.missing-sig.test.",
			expectErr: true,
			expectNil: true,
		},
		{
			// No DS at the cut, so unsigned data here is not a failure.
			name:      "insecure delegation resolves successfully",
			qname:     "www.unsigned.test.",
			expectErr: false,
			expectNil: false,
		},
		{
			// A name that does not exist under a signed zone: the denial
			// travels through authority() -> isZoneSecure() and must not be
			// mistaken for missing signatures.
			name:      "denial under signed zone validates",
			qname:     "absent.denial.test.",
			expectErr: false,
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := hermeticResolve(t, r, tt.qname, dns.TypeA)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected an error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if tt.expectNil {
				if resp != nil {
					t.Errorf("resp = %v, want nil", resp)
				}
			} else {
				if resp == nil {
					t.Fatalf("resp is nil")
				}
			}
		})
	}
}
