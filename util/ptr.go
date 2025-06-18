// Package util provides DNS protocol utilities for SDNS.
package util

import (
	"net"
	"strings"
)

const (
	// ReverseDomainV4 is the reverse DNS domain for IPv4 addresses.
	ReverseDomainV4 = ".in-addr.arpa."
	// ReverseDomainV6 is the reverse DNS domain for IPv6 addresses.
	ReverseDomainV6 = ".ip6.arpa."
)

// IPFromReverseName extracts an IP address from a PTR record name.
// For example:
// - "54.119.58.176.in-addr.arpa." returns "176.58.119.54"
// - "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." returns "2001:db8::567:89ab"
// Returns empty string if the name is not a valid PTR record.
func IPFromReverseName(name string) string {
	switch {
	case strings.HasSuffix(name, ReverseDomainV4):
		return parseIPv4PTR(name)
	case strings.HasSuffix(name, ReverseDomainV6):
		return parseIPv6PTR(name)
	default:
		return ""
	}
}

// CheckReverseName checks if a domain name is in a reverse DNS zone.
// Returns:
// - 0: not a reverse domain
// - 1: IPv4 reverse domain (.in-addr.arpa.)
// - 2: IPv6 reverse domain (.ip6.arpa.)
func CheckReverseName(name string) int {
	switch {
	case strings.HasSuffix(name, ReverseDomainV4):
		return 1
	case strings.HasSuffix(name, ReverseDomainV6):
		return 2
	default:
		return 0
	}
}

// parseIPv4PTR converts IPv4 PTR name to IP address.
func parseIPv4PTR(name string) string {
	// Remove the suffix
	parts := strings.TrimSuffix(name, ReverseDomainV4)

	// Split into octets
	octets := strings.Split(parts, ".")

	// Reverse the octets
	for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
		octets[i], octets[j] = octets[j], octets[i]
	}

	// Parse and validate
	ip := net.ParseIP(strings.Join(octets, "."))
	if ip == nil || ip.To4() == nil {
		return ""
	}

	return ip.String()
}

// parseIPv6PTR converts IPv6 PTR name to IP address.
func parseIPv6PTR(name string) string {
	// Remove the suffix
	parts := strings.TrimSuffix(name, ReverseDomainV6)

	// Split into nibbles (single hex digits)
	nibbles := strings.Split(parts, ".")

	// Reverse the nibbles
	for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}

	// Group nibbles into 16-bit segments
	var segments []string
	for i := 0; i < len(nibbles); i += 4 {
		end := i + 4
		if end > len(nibbles) {
			end = len(nibbles)
		}
		segment := strings.Join(nibbles[i:end], "")
		segments = append(segments, segment)
	}

	// Parse and validate
	ip := net.ParseIP(strings.Join(segments, ":"))
	if ip == nil || ip.To16() == nil {
		return ""
	}

	return ip.String()
}
