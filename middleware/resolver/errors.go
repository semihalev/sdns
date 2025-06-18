package resolver

import (
	"fmt"

	"github.com/miekg/dns"
)

// ValidationError represents a DNS validation error with EDE information.
type ValidationError struct {
	Code    uint16
	Message string
	Err     error
}

func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// (*ValidationError).EDECode EDECode returns the EDE code for this error.
func (e *ValidationError) EDECode() uint16 {
	return e.Code
}

// Common validation errors with EDE codes.
var (
	errNoDNSKEY = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No DNSKEY records found in response",
	}
	errMissingKSK = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No KSK DNSKEY matches DS records from parent",
	}
	errFailedToConvertKSK = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Unable to validate DNSKEY against parent DS record",
	}
	errMismatchingDS = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "DNSKEY does not match DS record from parent zone",
	}
	errNoSignatures = &ValidationError{
		Code:    dns.ExtendedErrorCodeRRSIGsMissing,
		Message: "Response is missing required RRSIG records",
	}
	errMissingDNSKEY = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No DNSKEY found to validate RRSIG",
	}
	errInvalidSignaturePeriod = &ValidationError{
		Code:    dns.ExtendedErrorCodeSignatureExpired,
		Message: "RRSIG validity period check failed",
	}
	errMissingSigned = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "RRsets covered by RRSIG are missing",
	}
	errDSRecords = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Parent has DS records but zone appears unsigned",
	}
)

// NSEC validation errors.
var (
	errNSECTypeExists = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC record indicates queried type exists",
	}
	errNSECMissingCoverage = &ValidationError{
		Code:    dns.ExtendedErrorCodeNSECMissing,
		Message: "Incomplete NSEC proof for name non-existence",
	}
	errNSECBadDelegation = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Invalid NSEC type bitmap for delegation",
	}
	errNSECNSMissing = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC missing NS bit at delegation point",
	}
	errNSECOptOut = &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC3 opt-out validation failed",
	}
)

// Network and authority errors.
var (
	errMaxDepth = &ValidationError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Maximum recursion depth exceeded",
	}
	errParentDetection = &ValidationError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Delegation loop detected",
	}
	errNoReachableAuth = &ValidationError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "No reachable authoritative servers",
	}
	errConnectionFailed = &ValidationError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "All authoritative servers failed",
	}
	errNoRootServers = &ValidationError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "Unable to reach root servers",
	}
)

// NewNetworkError creates a network error with EDE information.
func NewNetworkError(err error) *ValidationError {
	return &ValidationError{
		Code:    dns.ExtendedErrorCodeNetworkError,
		Message: "network error",
		Err:     err,
	}
}

// NewNoReachableAuthorityError creates an error for unreachable servers.
func NewNoReachableAuthorityError(message string) *ValidationError {
	return &ValidationError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: message,
	}
}

// NoReachableAuthAtZone creates an error with zone context.
func NoReachableAuthAtZone(zone string) *ValidationError {
	return &ValidationError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: fmt.Sprintf("at delegation %s", zone),
	}
}

// (*ValidationError).WithContext withContext creates a new ValidationError with additional context.
func (e *ValidationError) WithContext(format string, args ...any) *ValidationError {
	return &ValidationError{
		Code:    e.Code,
		Message: fmt.Sprintf(e.Message+" - "+format, args...),
		Err:     e.Err,
	}
}

// DNSKEYMissingForZone common error creation helpers.
func DNSKEYMissingForZone(zone string) *ValidationError {
	return &ValidationError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: fmt.Sprintf("No DNSKEY records found for %s", zone),
	}
}

func SignatureExpiredForRRset(rrtype string, zone string) *ValidationError {
	return &ValidationError{
		Code:    dns.ExtendedErrorCodeSignatureExpired,
		Message: fmt.Sprintf("RRSIG for %s in %s has expired", rrtype, zone),
	}
}
