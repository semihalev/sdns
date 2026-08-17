package dnssec

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
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
			expected: true, // When owner==next, everything except owner is covered
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nsecCovers(tt.owner, tt.next, tt.qname)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("result = %v, want %v", result, tt.expected)
			}
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

	err := VerifyNODATANSEC(msg, []dns.RR{nsec})
	if err != nil {
		t.Errorf("%s: unexpected error: %v", "Valid NODATA should verify successfully", err)
	}

	// Test case 2: Invalid - type exists
	nsec.TypeBitMap = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSOA}
	err = VerifyNODATANSEC(msg, []dns.RR{nsec})
	if !reflect.DeepEqual(ErrNSECTypeExists, err) {
		t.Errorf("%s: err = %v, want %v", "Should fail when type exists", err, ErrNSECTypeExists)
	}

	// Test case 3: DS query at delegation point
	msg.SetQuestion("example.com.", dns.TypeDS)
	nsec.TypeBitMap = []uint16{dns.TypeNS} // Delegation point (has NS, no SOA)
	err = VerifyNODATANSEC(msg, []dns.RR{nsec})
	if err != nil {
		t.Errorf("%s: unexpected error: %v", "Valid DS NODATA at delegation should verify", err)
	}

	// Test case 4: Invalid DS - has SOA (not a delegation)
	nsec.TypeBitMap = []uint16{dns.TypeNS, dns.TypeSOA}
	err = VerifyNODATANSEC(msg, []dns.RR{nsec})
	if !reflect.DeepEqual(ErrNSECBadDelegation, err) {
		t.Errorf("%s: err = %v, want %v", "Should fail when SOA exists at delegation", err, ErrNSECBadDelegation)
	}

	// Test case 5: No NSEC records
	err = VerifyNODATANSEC(msg, []dns.RR{})
	if !reflect.DeepEqual(ErrNSECMissingCoverage, err) {
		t.Errorf("%s: err = %v, want %v", "Should fail with no NSEC records", err, ErrNSECMissingCoverage)
	}
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

	err := VerifyNameErrorNSEC(msg, []dns.RR{nsec1, nsec2})
	if err != nil {
		t.Errorf("%s: unexpected error: %v", "Valid NXDOMAIN should verify successfully", err)
	}

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

	err = VerifyNameErrorNSEC(msg, []dns.RR{nsecNoCover})
	if !reflect.DeepEqual(ErrNSECMissingCoverage, err) {
		t.Errorf("%s: err = %v, want %v", "Should fail when no NSEC covers the name", err, ErrNSECMissingCoverage)
	}

	// Test case 3: No NSEC records
	err = VerifyNameErrorNSEC(msg, []dns.RR{})
	if !reflect.DeepEqual(ErrNSECMissingCoverage, err) {
		t.Errorf("%s: err = %v, want %v", "Should fail with no NSEC records", err, ErrNSECMissingCoverage)
	}
}

// TestVerifyNODATANSEC_Wildcard locks in the RFC 4035 §3.1.3.4 wildcard
// NODATA shape: qname does not exist directly, but a wildcard owner
// *.closest-encloser exists with a bitmap that omits the queried type.
func TestVerifyNODATANSEC_Wildcard(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("a.z.w.example.", dns.TypeAAAA)

	// NSEC covering a.z.w.example. (no direct owner).
	covering := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.w.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "zz.w.example.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	// Wildcard NSEC at *.w.example. — type bitmap has A but not AAAA.
	wildcard := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "*.w.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "a.w.example.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	err := VerifyNODATANSEC(msg, []dns.RR{covering, wildcard})
	if err != nil {
		t.Errorf("%s: unexpected error: %v", "Wildcard NODATA proof should verify", err)
	}

	// Same shape but wildcard bitmap *does* include the queried type —
	// must be rejected because the wildcard could synthesize an answer.
	wildcardWithType := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "*.w.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "a.w.example.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	err = VerifyNODATANSEC(msg, []dns.RR{covering, wildcardWithType})
	if !reflect.DeepEqual(ErrNSECTypeExists, err) {
		t.Errorf("err = %v, want %v", err, ErrNSECTypeExists)
	}
}
