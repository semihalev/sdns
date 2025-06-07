package util

import (
	"errors"

	"github.com/miekg/dns"
)

// SetEDE adds an Extended DNS Error to the response
func SetEDE(msg *dns.Msg, code uint16, extraText string) {
	opt := msg.IsEdns0()
	if opt == nil {
		return // No EDNS0 support, skip EDE
	}

	// Add the EDE option
	ede := &dns.EDNS0_EDE{
		InfoCode:  code,
		ExtraText: extraText,
	}
	opt.Option = append(opt.Option, ede)
}

// GetEDE extracts Extended DNS Error from a message if present
func GetEDE(msg *dns.Msg) *dns.EDNS0_EDE {
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if ede, ok := option.(*dns.EDNS0_EDE); ok {
			return ede
		}
	}
	return nil
}

// SetRcodeWithEDE returns message with specified rcode and Extended DNS Error
func SetRcodeWithEDE(req *dns.Msg, rcode int, do bool, edeCode uint16, extraText string) *dns.Msg {
	m := SetRcode(req, rcode, do)
	if rcode == dns.RcodeServerFailure {
		SetEDE(m, edeCode, extraText)
	}
	return m
}

// ErrorToEDE maps errors to Extended DNS Error codes efficiently
func ErrorToEDE(err error) (uint16, string) {
	if err == nil {
		return dns.ExtendedErrorCodeOther, ""
	}

	// Check if it's a ValidationError with EDE info
	type eder interface {
		EDECode() uint16
	}

	if ve, ok := err.(eder); ok {
		code := ve.EDECode()
		// If we got a specific code, use it
		if code != 0 {
			return code, err.Error()
		}
	}

	// Check for wrapped error with EDE method
	type validationError interface {
		EDECode() uint16
		Error() string
	}

	var ve validationError
	if errors.As(err, &ve) {
		return ve.EDECode(), ve.Error()
	}

	// For other errors, check common patterns
	errStr := err.Error()

	// Network errors - check for common patterns
	switch {
	case isNetworkError(errStr):
		return dns.ExtendedErrorCodeNetworkError, "Network error"
	case isNoServerError(errStr):
		return dns.ExtendedErrorCodeNoReachableAuthority, "No reachable authority servers"
	default:
		// For untyped errors, return generic
		return dns.ExtendedErrorCodeOther, ""
	}
}

// isNetworkError checks for common network error patterns
func isNetworkError(s string) bool {
	// Check for common network error substrings
	return len(s) > 7 && (containsAny(s, "timeout", "refused", "unreachable", "no route"))
}

// isNoServerError checks for no server errors
func isNoServerError(s string) bool {
	return len(s) > 9 && containsAny(s, "no servers", "failed to upstream")
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if contains(s, substr) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
