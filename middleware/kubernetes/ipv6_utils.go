package kubernetes

import (
	"net"
	"strings"
)

// ParsePodIP parses both IPv4 and IPv6 pod query formats
// IPv4: 10-244-1-1.namespace.pod.cluster.local
// IPv6: 2001-db8--1.namespace.pod.cluster.local or
//
//	2001-0db8-0000-0000-0000-0000-0000-0001.namespace.pod.cluster.local
func ParsePodIP(podPart string) net.IP {
	// Try IPv4 format first (most common)
	if ip := parseIPv4Pod(podPart); ip != nil {
		return ip
	}

	// Try IPv6 formats
	return parseIPv6Pod(podPart)
}

// parseIPv4Pod parses IPv4 pod format: 10-244-1-1
func parseIPv4Pod(s string) net.IP {
	parts := strings.Split(s, "-")
	if len(parts) != IPv4AddressSize {
		return nil
	}

	ipStr := strings.Join(parts, ".")
	ip := net.ParseIP(ipStr)
	if ip != nil && ip.To4() != nil {
		return ip
	}
	return nil
}

// parseIPv6Pod parses IPv6 pod formats
func parseIPv6Pod(s string) net.IP {
	// Format 1: Full format with all groups
	// 2001-0db8-0000-0000-0000-0000-0000-0001
	if strings.Count(s, "-") == 7 { // IPv6 has 8 groups, so 7 separators
		ipStr := strings.ReplaceAll(s, "-", ":")
		return net.ParseIP(ipStr)
	}

	// Format 2: Compressed format with --
	// 2001-db8--1 -> 2001:db8::1
	if strings.Contains(s, "--") {
		ipStr := strings.ReplaceAll(s, "--", "::")
		ipStr = strings.ReplaceAll(ipStr, "-", ":")
		return net.ParseIP(ipStr)
	}

	// Format 3: Try replacing all - with :
	// fd00-1-2-3-4-5-6-7
	if strings.Count(s, "-") >= 3 {
		ipStr := strings.ReplaceAll(s, "-", ":")
		if ip := net.ParseIP(ipStr); ip != nil && ip.To4() == nil {
			return ip
		}
	}

	return nil
}

// FormatPodIP formats an IP for pod DNS name
// IPv4: 10.244.1.1 -> 10-244-1-1
// IPv6: 2001:db8::1 -> 2001-db8--1
func FormatPodIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4 format
		parts := strings.Split(ip4.String(), ".")
		return strings.Join(parts, "-")
	}

	// IPv6 format - use compressed form
	ipStr := ip.String()

	// Replace :: with --
	ipStr = strings.ReplaceAll(ipStr, "::", "--")

	// Replace remaining : with -
	ipStr = strings.ReplaceAll(ipStr, ":", "-")

	return ipStr
}

// ParseReverseIP parses both IPv4 and IPv6 reverse queries
// IPv4: 1.0.96.10.in-addr.arpa -> 10.96.0.1
// IPv6: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
func ParseReverseIP(labels []string) (net.IP, bool) {
	if len(labels) < 2 {
		return nil, false
	}

	// Check suffix
	suffix := strings.Join(labels[len(labels)-2:], ".")

	switch suffix {
	case "in-addr.arpa":
		return parseReverseIPv4(labels)
	case "ip6.arpa":
		return parseReverseIPv6(labels)
	default:
		return nil, false
	}
}

// parseReverseIPv4 parses IPv4 reverse: d.c.b.a.in-addr.arpa -> a.b.c.d
func parseReverseIPv4(labels []string) (net.IP, bool) {
	if len(labels) != 6 { // d.c.b.a.in-addr.arpa = 4 octets + 2 suffix parts
		return nil, false
	}

	// Reverse the octets
	octets := make([]string, IPv4AddressSize)
	for i := 0; i < IPv4AddressSize; i++ {
		octets[i] = labels[3-i]
	}

	ipStr := strings.Join(octets, ".")
	ip := net.ParseIP(ipStr)
	return ip, ip != nil
}

// parseReverseIPv6 parses IPv6 reverse
// Example: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
// Result: 2001:db8::1
func parseReverseIPv6(labels []string) (net.IP, bool) {
	// IPv6 reverse has 32 nibbles + ip6.arpa = 34 labels
	if len(labels) != 34 { // 32 nibbles + 2 suffix parts
		return nil, false
	}

	// Collect nibbles in reverse order
	nibbles := make([]string, 32) // IPv6 has 128 bits = 32 nibbles
	for i := 0; i < 32; i++ {
		nibbles[i] = labels[31-i]
	}

	// Group into 16-bit segments
	var segments []string
	for i := 0; i < 32; i += 4 { // 4 nibbles = 16 bits = 1 segment
		segment := nibbles[i] + nibbles[i+1] + nibbles[i+2] + nibbles[i+3]
		// Skip leading zeros in segment
		segment = strings.TrimLeft(segment, "0")
		if segment == "" {
			segment = "0"
		}
		segments = append(segments, segment)
	}

	// Join segments
	ipStr := strings.Join(segments, ":")

	// Compress consecutive zeros (find longest run)
	ipStr = compressIPv6(ipStr)

	ip := net.ParseIP(ipStr)
	return ip, ip != nil
}

// compressIPv6 compresses consecutive zero segments
func compressIPv6(ipStr string) string {
	segments := strings.Split(ipStr, ":")

	// Find longest run of zeros
	maxStart, maxLen := -1, 0
	currStart, currLen := -1, 0

	for i, seg := range segments {
		if seg == "0" {
			if currStart == -1 {
				currStart = i
			}
			currLen++
		} else {
			if currLen > maxLen {
				maxStart = currStart
				maxLen = currLen
			}
			currStart = -1
			currLen = 0
		}
	}

	// Check last run
	if currLen > maxLen {
		maxStart = currStart
		maxLen = currLen
	}

	// Compress if we found a run of 2+ zeros
	if maxLen >= 2 { // Only compress runs of 2 or more zeros
		before := segments[:maxStart]
		after := segments[maxStart+maxLen:]

		compressed := strings.Join(before, ":")
		if len(before) > 0 {
			compressed += ":"
		}
		compressed += ":"
		if len(after) > 0 {
			compressed += strings.Join(after, ":")
		}

		return compressed
	}

	return ipStr
}

// FormatReverseIP formats an IP for reverse DNS
// IPv4: 10.96.0.1 -> 1.0.96.10.in-addr.arpa
// IPv6: 2001:db8::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
func FormatReverseIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4 reverse
		parts := strings.Split(ip4.String(), ".")
		for i := 0; i < 2; i++ { // Swap first 2 with last 2 octets
			parts[i], parts[3-i] = parts[3-i], parts[i]
		}
		return strings.Join(parts, ".") + ".in-addr.arpa."
	}

	// IPv6 reverse
	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}

	// Convert to nibbles
	var nibbles []string
	for i := len(ip6) - 1; i >= 0; i-- {
		nibbles = append(nibbles, string("0123456789abcdef"[ip6[i]&0xF])) // Low nibble
		nibbles = append(nibbles, string("0123456789abcdef"[ip6[i]>>4]))  // High nibble
	}

	return strings.Join(nibbles, ".") + ".ip6.arpa."
}
