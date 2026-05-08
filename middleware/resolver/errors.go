package resolver

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// Network and authority errors. DNSSEC-specific sentinels live in
// the dnssec package.
var (
	errMaxDepth = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Maximum recursion depth exceeded",
	}
	errParentDetection = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Delegation loop detected",
	}
	errNoReachableAuth = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "No reachable authoritative servers",
	}
	errConnectionFailed = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "All authoritative servers failed",
	}
	errNoRootServers = &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "Unable to reach root servers",
	}
)

// NewNetworkError creates a network error with EDE information.
func NewNetworkError(err error) *dnsutil.EDEError {
	return &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNetworkError,
		Message: "network error",
		Err:     err,
	}
}

// NewNoReachableAuthorityError creates an error for unreachable servers.
func NewNoReachableAuthorityError(message string) *dnsutil.EDEError {
	return &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: message,
	}
}

// NoReachableAuthAtZone creates an error with zone context.
func NoReachableAuthAtZone(zone string) *dnsutil.EDEError {
	return &dnsutil.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: fmt.Sprintf("at delegation %s", zone),
	}
}
