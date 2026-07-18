package dnssec

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// DNSKEY-side validation errors.
var (
	ErrNoDNSKEY = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No DNSKEY records found in response",
	}
	ErrMissingKSK = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No KSK DNSKEY matches DS records from parent",
	}
	ErrFailedToConvertKSK = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Unable to validate DNSKEY against parent DS record",
	}
	ErrMismatchingDS = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "DNSKEY does not match DS record from parent zone",
	}
	ErrNoSignatures = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeRRSIGsMissing,
		Message: "Response is missing required RRSIG records",
	}
	ErrMissingDNSKEY = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No DNSKEY found to validate RRSIG",
	}
	ErrInvalidSignaturePeriod = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeSignatureExpired,
		Message: "RRSIG validity period check failed",
	}
	ErrMissingSigned = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "RRsets covered by RRSIG are missing",
	}
	ErrDSRecords = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Parent has DS records but zone appears unsigned",
	}
	ErrTrustAnchorsUnavailable = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Trust anchors unavailable — refusing to validate",
	}
)

// NSEC / NSEC3 denial-of-existence errors.
var (
	ErrNSECTypeExists = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC record indicates queried type exists",
	}
	ErrNSECMissingCoverage = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNSECMissing,
		Message: "Incomplete NSEC proof for name non-existence",
	}
	ErrNSECBadDelegation = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Invalid NSEC type bitmap for delegation",
	}
	ErrNSECNSMissing = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC missing NS bit at delegation point",
	}
	ErrNSECOptOut = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC3 opt-out validation failed",
	}
	ErrWildcardNoDenial = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Wildcard-expanded answer lacks NSEC/NSEC3 proof of no closer match",
	}
)

// DNSKEYMissingForZone returns a DNSKEY-missing error tagged with zone.
func DNSKEYMissingForZone(zone string) *dnsutil.EDEError {
	return &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: fmt.Sprintf("No DNSKEY records found for %s", zone),
	}
}

// SignatureExpiredForRRset returns a signature-expired error tagged with
// the RR type and zone.
func SignatureExpiredForRRset(rrtype, zone string) *dnsutil.EDEError {
	return &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeSignatureExpired,
		Message: fmt.Sprintf("RRSIG for %s in %s has expired", rrtype, zone),
	}
}
