package resolver

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
	"github.com/stretchr/testify/assert"
)

func TestEDEError(t *testing.T) {
	// Test Error() with wrapped error
	wrapped := errors.New("wrapped error")
	err := &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNetworkError,
		Message: "network failed",
		Err:     wrapped,
	}
	assert.Contains(t, err.Error(), "network failed")
	assert.Contains(t, err.Error(), "wrapped error")

	// Test Error() without wrapped error
	errNoWrap := &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "bogus response",
	}
	assert.Equal(t, "bogus response", errNoWrap.Error())

	// Test Unwrap()
	assert.Equal(t, wrapped, err.Unwrap())
	assert.Nil(t, errNoWrap.Unwrap())

	// Test EDECode()
	assert.Equal(t, dns.ExtendedErrorCodeNetworkError, err.EDECode())
}

func TestNewNetworkError(t *testing.T) {
	wrapped := errors.New("connection refused")
	err := NewNetworkError(wrapped)

	assert.Equal(t, dns.ExtendedErrorCodeNetworkError, err.Code)
	assert.Equal(t, "network error", err.Message)
	assert.Equal(t, wrapped, err.Err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestNewNoReachableAuthorityError(t *testing.T) {
	err := NewNoReachableAuthorityError("all servers timed out")

	assert.Equal(t, dns.ExtendedErrorCodeNoReachableAuthority, err.Code)
	assert.Equal(t, "all servers timed out", err.Message)
	assert.Nil(t, err.Err)
}

func TestNoReachableAuthAtZone(t *testing.T) {
	err := NoReachableAuthAtZone("example.com.")

	assert.Equal(t, dns.ExtendedErrorCodeNoReachableAuthority, err.Code)
	assert.Contains(t, err.Message, "example.com.")
	assert.Contains(t, err.Message, "delegation")
}

func TestEDEErrorWithContext(t *testing.T) {
	original := &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "validation failed",
	}

	withCtx := original.WithContext("zone %s", "example.com.")

	assert.Equal(t, dns.ExtendedErrorCodeDNSBogus, withCtx.Code)
	assert.Contains(t, withCtx.Message, "validation failed")
	assert.Contains(t, withCtx.Message, "example.com.")
}

func TestDNSKEYMissingForZone(t *testing.T) {
	err := dnssec.DNSKEYMissingForZone("secure.example.com.")

	assert.Equal(t, dns.ExtendedErrorCodeDNSKEYMissing, err.Code)
	assert.Contains(t, err.Message, "secure.example.com.")
	assert.Contains(t, err.Message, "DNSKEY")
}

func TestSignatureExpiredForRRset(t *testing.T) {
	err := dnssec.SignatureExpiredForRRset("A", "example.com.")

	assert.Equal(t, dns.ExtendedErrorCodeSignatureExpired, err.Code)
	assert.Contains(t, err.Message, "A")
	assert.Contains(t, err.Message, "example.com.")
	assert.Contains(t, err.Message, "expired")
}

func TestPredefinedEDEErrors(t *testing.T) {
	// Test that predefined errors have correct codes
	tests := []struct {
		name string
		err  *dnsutil.EDEError
		code uint16
	}{
		{"dnssec.ErrNoDNSKEY", dnssec.ErrNoDNSKEY, dns.ExtendedErrorCodeDNSKEYMissing},
		{"dnssec.ErrMissingKSK", dnssec.ErrMissingKSK, dns.ExtendedErrorCodeDNSKEYMissing},
		{"dnssec.ErrNoSignatures", dnssec.ErrNoSignatures, dns.ExtendedErrorCodeRRSIGsMissing},
		{"dnssec.ErrInvalidSignaturePeriod", dnssec.ErrInvalidSignaturePeriod, dns.ExtendedErrorCodeSignatureExpired},
		{"dnssec.ErrNSECMissingCoverage", dnssec.ErrNSECMissingCoverage, dns.ExtendedErrorCodeNSECMissing},
		{"errNoReachableAuth", errNoReachableAuth, dns.ExtendedErrorCodeNoReachableAuthority},
		{"errMaxDepth", errMaxDepth, dns.ExtendedErrorCodeOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, tt.err.EDECode())
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}
