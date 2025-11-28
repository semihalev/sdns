package util

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestSetRcodeWithEDE(t *testing.T) {
	tests := []struct {
		name     string
		req      *dns.Msg
		rcode    int
		do       bool
		edeCode  uint16
		edeText  string
		expected func(*testing.T, *dns.Msg)
	}{
		{
			name: "SERVFAIL with DO bit set",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, false) // Add EDNS0 to request
				return m
			}(),
			rcode:   dns.RcodeServerFailure,
			do:      true,
			edeCode: dns.ExtendedErrorCodeDNSSECIndeterminate,
			edeText: "DNSSEC validation failure",
			expected: func(t *testing.T, msg *dns.Msg) {
				assert.Equal(t, dns.RcodeServerFailure, msg.Rcode)
				assert.Len(t, msg.Extra, 1)
				opt, ok := msg.Extra[0].(*dns.OPT)
				assert.True(t, ok)
				assert.True(t, opt.Do())
				assert.Len(t, opt.Option, 1)
				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				assert.True(t, ok)
				assert.Equal(t, dns.ExtendedErrorCodeDNSSECIndeterminate, ede.InfoCode)
				assert.Equal(t, "DNSSEC validation failure", ede.ExtraText)
			},
		},
		{
			name: "SERVFAIL without DO bit",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, false)
				return m
			}(),
			rcode:   dns.RcodeServerFailure,
			do:      false,
			edeCode: dns.ExtendedErrorCodeNetworkError,
			edeText: "Network unreachable",
			expected: func(t *testing.T, msg *dns.Msg) {
				assert.Equal(t, dns.RcodeServerFailure, msg.Rcode)
				opt := msg.IsEdns0()
				assert.NotNil(t, opt)
				assert.False(t, opt.Do())
				assert.Len(t, opt.Option, 1) // EDE is added for SERVFAIL
			},
		},
		{
			name: "Non-SERVFAIL with DO bit",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, false)
				return m
			}(),
			rcode:   dns.RcodeNameError,
			do:      true,
			edeCode: dns.ExtendedErrorCodeCachedError,
			edeText: "Cached negative response",
			expected: func(t *testing.T, msg *dns.Msg) {
				assert.Equal(t, dns.RcodeNameError, msg.Rcode)
				opt := msg.IsEdns0()
				assert.NotNil(t, opt)
				assert.True(t, opt.Do())
				assert.Len(t, opt.Option, 0) // No EDE for non-SERVFAIL
			},
		},
		{
			name: "Empty EDE text",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, false)
				return m
			}(),
			rcode:   dns.RcodeServerFailure,
			do:      true,
			edeCode: dns.ExtendedErrorCodeOther,
			edeText: "",
			expected: func(t *testing.T, msg *dns.Msg) {
				assert.Equal(t, dns.RcodeServerFailure, msg.Rcode)
				assert.Len(t, msg.Extra, 1)
				opt, ok := msg.Extra[0].(*dns.OPT)
				assert.True(t, ok)
				assert.Len(t, opt.Option, 1)
				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				assert.True(t, ok)
				assert.Equal(t, dns.ExtendedErrorCodeOther, ede.InfoCode)
				assert.Equal(t, "", ede.ExtraText)
			},
		},
		{
			name: "Request with existing OPT record",
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetEdns0(512, false)
				return m
			}(),
			rcode:   dns.RcodeServerFailure,
			do:      true,
			edeCode: dns.ExtendedErrorCodeNoReachableAuthority,
			edeText: "All nameservers unreachable",
			expected: func(t *testing.T, msg *dns.Msg) {
				assert.Equal(t, dns.RcodeServerFailure, msg.Rcode)
				assert.Len(t, msg.Extra, 1)
				opt, ok := msg.Extra[0].(*dns.OPT)
				assert.True(t, ok)
				assert.Len(t, opt.Option, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := SetRcodeWithEDE(tt.req, tt.rcode, tt.do, tt.edeCode, tt.edeText)
			tt.expected(t, msg)
		})
	}
}

func TestErrorToEDE(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode uint16
		expectedText string
	}{
		{
			name:         "nil error",
			err:          nil,
			expectedCode: dns.ExtendedErrorCodeOther,
			expectedText: "",
		},
		{
			name:         "context deadline exceeded",
			err:          context.DeadlineExceeded,
			expectedCode: dns.ExtendedErrorCodeNoReachableAuthority,
			expectedText: "Query timeout exceeded",
		},
		{
			name:         "wrapped context deadline",
			err:          fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
			expectedCode: dns.ExtendedErrorCodeNoReachableAuthority,
			expectedText: "Query timeout exceeded",
		},
		{
			name:         "context canceled",
			err:          context.Canceled,
			expectedCode: dns.ExtendedErrorCodeOther,
			expectedText: "Query was cancelled",
		},
		{
			name:         "DNSSEC validation error with EDE",
			err:          &mockEDEError{code: dns.ExtendedErrorCodeDNSSECIndeterminate, text: "DNSSEC validation failure"},
			expectedCode: dns.ExtendedErrorCodeDNSSECIndeterminate,
			expectedText: "DNSSEC validation failure",
		},
		{
			name:         "Network error with EDE",
			err:          &mockEDEError{code: dns.ExtendedErrorCodeNetworkError, text: "Network unreachable"},
			expectedCode: dns.ExtendedErrorCodeNetworkError,
			expectedText: "Network unreachable",
		},
		{
			name:         "generic error",
			err:          errors.New("something went wrong"),
			expectedCode: dns.ExtendedErrorCodeOther,
			expectedText: "something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, text := ErrorToEDE(tt.err)
			assert.Equal(t, tt.expectedCode, code)
			assert.Equal(t, tt.expectedText, text)
		})
	}
}

func TestGetEDE(t *testing.T) {
	tests := []struct {
		name         string
		msg          *dns.Msg
		expectedCode uint16
		expectedText string
		expectNil    bool
	}{
		{
			name: "Message with EDE",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, false)
				opt := m.IsEdns0()
				ede := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeDNSSECIndeterminate,
					ExtraText: "DNSSEC validation failed",
				}
				opt.Option = append(opt.Option, ede)
				return m
			}(),
			expectedCode: dns.ExtendedErrorCodeDNSSECIndeterminate,
			expectedText: "DNSSEC validation failed",
			expectNil:    false,
		},
		{
			name: "Message without EDNS0",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			expectNil: true,
		},
		{
			name: "Message with EDNS0 but no EDE",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, false)
				return m
			}(),
			expectNil: true,
		},
		{
			name: "Message with EDNS0 and other options but no EDE",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, false)
				opt := m.IsEdns0()
				nsid := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}
				opt.Option = append(opt.Option, nsid)
				return m
			}(),
			expectNil: true,
		},
		{
			name: "Message with multiple EDE options - returns first",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, false)
				opt := m.IsEdns0()
				ede1 := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeNetworkError,
					ExtraText: "First EDE",
				}
				ede2 := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeNoReachableAuthority,
					ExtraText: "Second EDE",
				}
				opt.Option = append(opt.Option, ede1, ede2)
				return m
			}(),
			expectedCode: dns.ExtendedErrorCodeNetworkError,
			expectedText: "First EDE",
			expectNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ede := GetEDE(tt.msg)

			if tt.expectNil {
				assert.Nil(t, ede)
			} else {
				assert.NotNil(t, ede)
				assert.Equal(t, tt.expectedCode, ede.InfoCode)
				assert.Equal(t, tt.expectedText, ede.ExtraText)
			}
		})
	}
}

func TestSetEDE(t *testing.T) {
	tests := []struct {
		name      string
		msg       *dns.Msg
		code      uint16
		text      string
		expectEDE bool
	}{
		{
			name: "Add EDE to message with EDNS0",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(4096, false)
				return m
			}(),
			code:      dns.ExtendedErrorCodeDNSSECIndeterminate,
			text:      "Test error",
			expectEDE: true,
		},
		{
			name: "No EDE added without EDNS0",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			code:      dns.ExtendedErrorCodeOther,
			text:      "Test error",
			expectEDE: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetEDE(tt.msg, tt.code, tt.text)

			ede := GetEDE(tt.msg)
			if tt.expectEDE {
				assert.NotNil(t, ede)
				assert.Equal(t, tt.code, ede.InfoCode)
				assert.Equal(t, tt.text, ede.ExtraText)
			} else {
				assert.Nil(t, ede)
			}
		})
	}
}

// Mock error type with EDE support.
type mockEDEError struct {
	code uint16
	text string
}

func (e *mockEDEError) Error() string   { return e.text }
func (e *mockEDEError) EDECode() uint16 { return e.code }
