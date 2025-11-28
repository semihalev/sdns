package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPFromReverseName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid IPv4 PTR",
			input:    "54.119.58.176.in-addr.arpa.",
			expected: "176.58.119.54",
		},
		{
			name:     "Valid IPv4 PTR localhost",
			input:    "1.0.0.127.in-addr.arpa.",
			expected: "127.0.0.1",
		},
		{
			name:     "Valid IPv6 PTR full",
			input:    "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			expected: "2001:db8::567:89ab",
		},
		{
			name:     "Valid IPv6 PTR localhost",
			input:    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			expected: "::1",
		},
		{
			name:     "Not a PTR record",
			input:    "example.com.",
			expected: "",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Invalid IPv4 (too many octets)",
			input:    "1.2.3.4.5.in-addr.arpa.",
			expected: "",
		},
		{
			name:     "Invalid IPv4 (non-numeric)",
			input:    "a.b.c.d.in-addr.arpa.",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IPFromReverseName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckReverseName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "IPv4 reverse domain",
			input:    "54.119.58.176.in-addr.arpa.",
			expected: 1,
		},
		{
			name:     "IPv6 reverse domain",
			input:    "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			expected: 2,
		},
		{
			name:     "Not a reverse domain",
			input:    "example.com.",
			expected: 0,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: 0,
		},
		{
			name:     "Partial match (not suffix)",
			input:    "in-addr.arpa.example.com.",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckReverseName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseIPv4PTR(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard IPv4 PTR",
			input:    "1.2.3.4.in-addr.arpa.",
			expected: "4.3.2.1",
		},
		{
			name:     "IPv4 PTR with zeros",
			input:    "0.0.0.0.in-addr.arpa.",
			expected: "0.0.0.0",
		},
		{
			name:     "IPv4 PTR max values",
			input:    "255.255.255.255.in-addr.arpa.",
			expected: "255.255.255.255",
		},
		{
			name:     "Invalid: too few octets",
			input:    "1.2.3.in-addr.arpa.",
			expected: "",
		},
		{
			name:     "Invalid: non-numeric",
			input:    "a.b.c.d.in-addr.arpa.",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIPv4PTR(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseIPv6PTR(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IPv6 PTR full address",
			input:    "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			expected: "2001:db8::567:89ab",
		},
		{
			name:     "IPv6 PTR all zeros (::)",
			input:    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			expected: "::",
		},
		{
			name:     "IPv6 PTR loopback (::1)",
			input:    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			expected: "::1",
		},
		{
			name:     "IPv6 PTR full expanded",
			input:    "1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.ip6.arpa.",
			expected: "fed:cba9:8765:4321:fed:cba9:8765:4321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIPv6PTR(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
