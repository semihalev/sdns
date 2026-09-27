package dnsutil

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// EDEError is an error that carries an Extended DNS Error code (RFC
// 8914). Network and DNSSEC validation paths return EDEError values so
// that the response builder can copy the code straight into the EDE
// option without re-classifying string messages.
type EDEError struct {
	Code    uint16
	Message string
	Err     error
}

func (e *EDEError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *EDEError) Unwrap() error { return e.Err }

// EDECode returns the Extended DNS Error code for this error.
func (e *EDEError) EDECode() uint16 { return e.Code }

// WithContext returns a new EDEError whose Message is e.Message followed
// by the formatted context. Useful for tagging a generic sentinel with
// the zone or qname that triggered it without losing the code.
func (e *EDEError) WithContext(format string, args ...any) *EDEError {
	return &EDEError{
		Code:    e.Code,
		Message: fmt.Sprintf(e.Message+" - "+format, args...),
		Err:     e.Err,
	}
}

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

// PrependEDE puts an Extended DNS Error first on msg's OPT, on a copy of
// it: a message's OPT can be the very record the request carries, still in
// use, and the cache keeps a message's first EDE only. A message without
// an OPT gets one; the client-facing EDNS layer sets its size and flags,
// or drops it for a client without EDNS.
func PrependEDE(msg *dns.Msg, code uint16, extraText string) {
	ede := &dns.EDNS0_EDE{InfoCode: code, ExtraText: extraText}
	for i, rr := range msg.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		own := &dns.OPT{Hdr: opt.Hdr}
		own.Option = append(append(make([]dns.EDNS0, 0, len(opt.Option)+1), ede), opt.Option...)
		extra := append([]dns.RR(nil), msg.Extra...)
		extra[i] = own
		msg.Extra = extra
		return
	}
	own := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	own.SetUDPSize(DefaultMsgSize)
	own.Option = []dns.EDNS0{ede}
	msg.Extra = append(msg.Extra[:len(msg.Extra):len(msg.Extra)], own)
}

// IsUnsupportedDSEDE reports whether code says an answer is insecure
// because every DS its zone has names an algorithm or a digest the
// validator does not verify (RFC 8914 §4.2, §4.3).
func IsUnsupportedDSEDE(code uint16) bool {
	return code == dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm ||
		code == dns.ExtendedErrorCodeUnsupportedDSDigestType
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
