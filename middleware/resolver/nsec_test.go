package resolver

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestNSECCovers(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		next     string
		qname    string
		expected bool
	}{
		{
			name:     "normal case - name in range",
			owner:    "a.example.com.",
			next:     "c.example.com.",
			qname:    "b.example.com.",
			expected: true,
		},
		{
			name:     "normal case - name not in range",
			owner:    "a.example.com.",
			next:     "c.example.com.",
			qname:    "d.example.com.",
			expected: false,
		},
		{
			name:     "wrap-around case - name after owner",
			owner:    "z.example.com.",
			next:     "a.example.com.",
			qname:    "zz.example.com.",
			expected: true,
		},
		{
			name:     "wrap-around case - name before next",
			owner:    "z.example.com.",
			next:     "b.example.com.",
			qname:    "a.example.com.",
			expected: true,
		},
		{
			name:     "exact match with owner",
			owner:    "a.example.com.",
			next:     "b.example.com.",
			qname:    "a.example.com.",
			expected: false,
		},
		{
			name:     "exact match with next",
			owner:    "a.example.com.",
			next:     "b.example.com.",
			qname:    "b.example.com.",
			expected: false,
		},
		{
			name:     "same owner and next",
			owner:    "a.example.com.",
			next:     "a.example.com.",
			qname:    "b.example.com.",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nsecCovers(tt.owner, tt.next, tt.qname)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVerifyNODATANSEC(t *testing.T) {
	// Create a basic DNS message for testing
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeAAAA)

	// Test case 1: Valid NODATA - name exists but type doesn't
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "next.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA}, // No AAAA
	}

	err := verifyNODATANSEC(msg, []dns.RR{nsec})
	assert.NoError(t, err, "Valid NODATA should verify successfully")

	// Test case 2: Invalid - type exists
	nsec.TypeBitMap = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSOA}
	err = verifyNODATANSEC(msg, []dns.RR{nsec})
	assert.Equal(t, errNSECTypeExists, err, "Should fail when type exists")

	// Test case 3: DS query at delegation point
	msg.SetQuestion("example.com.", dns.TypeDS)
	nsec.TypeBitMap = []uint16{dns.TypeNS} // Delegation point (has NS, no SOA)
	err = verifyNODATANSEC(msg, []dns.RR{nsec})
	assert.NoError(t, err, "Valid DS NODATA at delegation should verify")

	// Test case 4: Invalid DS - has SOA (not a delegation)
	nsec.TypeBitMap = []uint16{dns.TypeNS, dns.TypeSOA}
	err = verifyNODATANSEC(msg, []dns.RR{nsec})
	assert.Equal(t, errNSECBadDelegation, err, "Should fail when SOA exists at delegation")

	// Test case 5: No NSEC records
	err = verifyNODATANSEC(msg, []dns.RR{})
	assert.Equal(t, errNSECMissingCoverage, err, "Should fail with no NSEC records")
}

func TestVerifyNameErrorNSEC(t *testing.T) {
	// Create a basic DNS message for testing
	msg := new(dns.Msg)
	msg.SetQuestion("b.example.com.", dns.TypeA)
	msg.SetRcode(msg, dns.RcodeNameError)

	// Test case 1: Valid NXDOMAIN - name doesn't exist
	nsec1 := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "a.example.com.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "c.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNS},
	}

	// NSEC proving no wildcard exists
	nsec2 := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "a.example.com.",
		TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS},
	}

	err := verifyNameErrorNSEC(msg, []dns.RR{nsec1, nsec2})
	assert.NoError(t, err, "Valid NXDOMAIN should verify successfully")

	// Test case 2: No covering NSEC
	nsecNoCover := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "d.example.com.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "e.example.com.",
		TypeBitMap: []uint16{dns.TypeA},
	}

	err = verifyNameErrorNSEC(msg, []dns.RR{nsecNoCover})
	assert.Equal(t, errNSECMissingCoverage, err, "Should fail when no NSEC covers the name")

	// Test case 3: No NSEC records
	err = verifyNameErrorNSEC(msg, []dns.RR{})
	assert.Equal(t, errNSECMissingCoverage, err, "Should fail with no NSEC records")
}
