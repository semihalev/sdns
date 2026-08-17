package resolver

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

func TestEDEError(t *testing.T) {
	// Test Error() with wrapped error
	wrapped := errors.New("wrapped error")
	err := &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNetworkError,
		Message: "network failed",
		Err:     wrapped,
	}
	if !strings.Contains(err.Error(), "network failed") {
		t.Errorf("%q does not contain %q", err.Error(), "network failed")
	}
	if !strings.Contains(err.Error(), "wrapped error") {
		t.Errorf("%q does not contain %q", err.Error(), "wrapped error")
	}

	// Test Error() without wrapped error
	errNoWrap := &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "bogus response",
	}
	if !reflect.DeepEqual("bogus response", errNoWrap.Error()) {
		t.Errorf("errNoWrap.Error() = %v, want %v", errNoWrap.Error(), "bogus response")
	}

	// Test Unwrap()
	if !reflect.DeepEqual(wrapped, err.Unwrap()) {
		t.Errorf("err.Unwrap() = %v, want %v", err.Unwrap(), wrapped)
	}
	if errNoWrap.Unwrap() != nil {
		t.Errorf("errNoWrap.Unwrap() = %v, want nil", errNoWrap.Unwrap())
	}

	// Test EDECode()
	if !reflect.DeepEqual(dns.ExtendedErrorCodeNetworkError, err.EDECode()) {
		t.Errorf("err.EDECode() = %v, want %v", err.EDECode(), dns.ExtendedErrorCodeNetworkError)
	}
}

func TestNewNetworkError(t *testing.T) {
	wrapped := errors.New("connection refused")
	err := NewNetworkError(wrapped)

	if !reflect.DeepEqual(dns.ExtendedErrorCodeNetworkError, err.Code) {
		t.Errorf("err.Code = %v, want %v", err.Code, dns.ExtendedErrorCodeNetworkError)
	}
	if !reflect.DeepEqual("network error", err.Message) {
		t.Errorf("err.Message = %v, want %v", err.Message, "network error")
	}
	if !reflect.DeepEqual(wrapped, err.Err) {
		t.Errorf("err.Err = %v, want %v", err.Err, wrapped)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("%q does not contain %q", err.Error(), "connection refused")
	}
}

func TestNewNoReachableAuthorityError(t *testing.T) {
	err := NewNoReachableAuthorityError("all servers timed out")

	if !reflect.DeepEqual(dns.ExtendedErrorCodeNoReachableAuthority, err.Code) {
		t.Errorf("err.Code = %v, want %v", err.Code, dns.ExtendedErrorCodeNoReachableAuthority)
	}
	if !reflect.DeepEqual("all servers timed out", err.Message) {
		t.Errorf("err.Message = %v, want %v", err.Message, "all servers timed out")
	}
	if err.Err != nil {
		t.Errorf("err.Err = %v, want nil", err.Err)
	}
}

func TestNoReachableAuthAtZone(t *testing.T) {
	err := NoReachableAuthAtZone("example.com.")

	if !reflect.DeepEqual(dns.ExtendedErrorCodeNoReachableAuthority, err.Code) {
		t.Errorf("err.Code = %v, want %v", err.Code, dns.ExtendedErrorCodeNoReachableAuthority)
	}
	if !strings.Contains(err.Message, "example.com.") {
		t.Errorf("%q does not contain %q", err.Message, "example.com.")
	}
	if !strings.Contains(err.Message, "delegation") {
		t.Errorf("%q does not contain %q", err.Message, "delegation")
	}
}

func TestEDEErrorWithContext(t *testing.T) {
	original := &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "validation failed",
	}

	withCtx := original.WithContext("zone %s", "example.com.")

	if !reflect.DeepEqual(dns.ExtendedErrorCodeDNSBogus, withCtx.Code) {
		t.Errorf("withCtx.Code = %v, want %v", withCtx.Code, dns.ExtendedErrorCodeDNSBogus)
	}
	if !strings.Contains(withCtx.Message, "validation failed") {
		t.Errorf("%q does not contain %q", withCtx.Message, "validation failed")
	}
	if !strings.Contains(withCtx.Message, "example.com.") {
		t.Errorf("%q does not contain %q", withCtx.Message, "example.com.")
	}
}

func TestDNSKEYMissingForZone(t *testing.T) {
	err := dnssec.DNSKEYMissingForZone("secure.example.com.")

	if !reflect.DeepEqual(dns.ExtendedErrorCodeDNSKEYMissing, err.Code) {
		t.Errorf("err.Code = %v, want %v", err.Code, dns.ExtendedErrorCodeDNSKEYMissing)
	}
	if !strings.Contains(err.Message, "secure.example.com.") {
		t.Errorf("%q does not contain %q", err.Message, "secure.example.com.")
	}
	if !strings.Contains(err.Message, "DNSKEY") {
		t.Errorf("%q does not contain %q", err.Message, "DNSKEY")
	}
}

func TestSignatureExpiredForRRset(t *testing.T) {
	err := dnssec.SignatureExpiredForRRset("A", "example.com.")

	if !reflect.DeepEqual(dns.ExtendedErrorCodeSignatureExpired, err.Code) {
		t.Errorf("err.Code = %v, want %v", err.Code, dns.ExtendedErrorCodeSignatureExpired)
	}
	if !strings.Contains(err.Message, "A") {
		t.Errorf("%q does not contain %q", err.Message, "A")
	}
	if !strings.Contains(err.Message, "example.com.") {
		t.Errorf("%q does not contain %q", err.Message, "example.com.")
	}
	if !strings.Contains(err.Message, "expired") {
		t.Errorf("%q does not contain %q", err.Message, "expired")
	}
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
			if !reflect.DeepEqual(tt.code, tt.err.EDECode()) {
				t.Errorf("tt.err.EDECode() = %v, want %v", tt.err.EDECode(), tt.code)
			}
			if len(tt.err.Error()) == 0 {
				t.Errorf("tt.err.Error() is empty")
			}
		})
	}
}
