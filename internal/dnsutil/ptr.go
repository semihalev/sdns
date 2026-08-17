// Package dnsutil provides DNS protocol utilities for SDNS.
package dnsutil

import (
	"net/netip"
	"strconv"
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

// parseIPv4PTR converts IPv4 PTR name to IP address. PTR is a large slice
// of real traffic, so this parses and formats by hand — one allocation,
// the returned string — where Split/Join/ParseIP/String paid six. The
// accepted shape is the RFC 1035 one: exactly four decimal labels, each
// 0-255 with no leading zero, reversed.
func parseIPv4PTR(name string) string {
	s := strings.TrimSuffix(name, ReverseDomainV4)

	var octets [4]int
	label := 0
	val, digits := 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			c := s[i]
			if c < '0' || c > '9' || digits == 3 {
				return ""
			}
			val = val*10 + int(c-'0')
			digits++
			continue
		}
		// Label boundary (or end): validate the finished octet. Leading
		// zeros are refused, matching net.ParseIP.
		if digits == 0 || val > 255 || (digits > 1 && s[i-digits] == '0') || label == 4 {
			return ""
		}
		octets[label] = val
		label++
		val, digits = 0, 0
	}
	if label != 4 {
		return ""
	}

	// The PTR labels spell the address reversed.
	var buf [15]byte
	out := buf[:0]
	for i := 3; i >= 0; i-- {
		out = strconv.AppendInt(out, int64(octets[i]), 10)
		if i > 0 {
			out = append(out, '.')
		}
	}
	return string(out)
}

// parseIPv6PTR converts IPv6 PTR name to IP address. The accepted shape is
// the RFC 3596 one — exactly 32 single-hex-digit labels, reversed — parsed
// straight into the address bytes; canonical formatting is the only
// allocation. The old Split/Join/ParseIP path incidentally admitted some
// truncated or multi-digit spellings no resolver emits; those now refuse,
// which downstream treats as an ordinary miss.
func parseIPv6PTR(name string) string {
	s := strings.TrimSuffix(name, ReverseDomainV6)

	// 32 nibbles separated by dots: 63 bytes exactly.
	if len(s) != 63 {
		return ""
	}
	var addr [16]byte
	for i := 0; i < 32; i++ {
		pos := i * 2
		if pos > 0 && s[pos-1] != '.' {
			return ""
		}
		c := s[pos]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return ""
		}
		// The labels spell the address reversed, low nibble first: label i
		// is nibble 31-i of the address.
		nibble := 31 - i
		if nibble%2 == 0 {
			addr[nibble/2] |= v << 4
		} else {
			addr[nibble/2] |= v
		}
	}

	return netip.AddrFrom16(addr).String()
}
