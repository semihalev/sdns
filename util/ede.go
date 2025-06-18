package util

import (
	"context"
	"errors"

	"github.com/miekg/dns"
)

// SetEDE adds an Extended DNS Error to the response.
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

// GetEDE extracts Extended DNS Error from a message if present.
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

// SetRcodeWithEDE returns message with specified rcode and Extended DNS Error.
func SetRcodeWithEDE(req *dns.Msg, rcode int, do bool, edeCode uint16, extraText string) *dns.Msg {
	m := SetRcode(req, rcode, do)
	if rcode == dns.RcodeServerFailure {
		SetEDE(m, edeCode, extraText)
	}
	return m
}

// ErrorToEDE maps errors to Extended DNS Error codes efficiently.
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

	// Handle common Go errors
	if errors.Is(err, context.DeadlineExceeded) {
		return dns.ExtendedErrorCodeNoReachableAuthority, "Query timeout exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return dns.ExtendedErrorCodeOther, "Query was cancelled"
	}

	// For remaining untyped errors, return generic with the error message
	return dns.ExtendedErrorCodeOther, err.Error()
}
