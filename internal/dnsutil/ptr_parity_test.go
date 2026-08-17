package dnsutil

import (
	"net"
	"strings"
	"testing"
)

// referenceIPv4PTR is the Split/Join/ParseIP implementation the manual
// parser replaced, kept as the parity oracle for well-formed names.
func referenceIPv4PTR(name string) string {
	parts := strings.TrimSuffix(name, ReverseDomainV4)
	octets := strings.Split(parts, ".")
	for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
		octets[i], octets[j] = octets[j], octets[i]
	}
	ip := net.ParseIP(strings.Join(octets, "."))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String()
}

func referenceIPv6PTR(name string) string {
	parts := strings.TrimSuffix(name, ReverseDomainV6)
	nibbles := strings.Split(parts, ".")
	for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}
	var segments []string
	for i := 0; i < len(nibbles); i += 4 {
		end := min(i+4, len(nibbles))
		segments = append(segments, strings.Join(nibbles[i:end], ""))
	}
	ip := net.ParseIP(strings.Join(segments, ":"))
	if ip == nil || ip.To16() == nil {
		return ""
	}
	return ip.String()
}

func TestParsePTRParity(t *testing.T) {
	v4 := []string{
		"1.0.0.10" + ReverseDomainV4,
		"54.119.58.176" + ReverseDomainV4,
		"255.255.255.255" + ReverseDomainV4,
		"0.0.0.0" + ReverseDomainV4,
		"1.2.3" + ReverseDomainV4,      // three labels: refuse
		"1.2.3.4.5" + ReverseDomainV4,  // five labels: refuse
		"256.0.0.1" + ReverseDomainV4,  // octet overflow: refuse
		"01.0.0.10" + ReverseDomainV4,  // leading zero: refuse (ParseIP rule)
		"a.0.0.10" + ReverseDomainV4,   // non-digit: refuse
		"1..0.10" + ReverseDomainV4,    // empty label: refuse
		"" + ReverseDomainV4,           // nothing: refuse
		"1234.0.0.1" + ReverseDomainV4, // over-long label: refuse
	}
	for _, name := range v4 {
		if got, want := parseIPv4PTR(name), referenceIPv4PTR(name); got != want {
			t.Fatalf("v4 %q: got %q, reference %q", name, got, want)
		}
	}

	// The RFC 3596 shape: 32 single-hex-digit labels.
	full := "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
	v6 := []string{
		full + ReverseDomainV6,
		strings.ToUpper(full) + ReverseDomainV6,
		strings.Repeat("0.", 31) + "0" + ReverseDomainV6,
		strings.Repeat("f.", 31) + "f" + ReverseDomainV6,
	}
	for _, name := range v6 {
		if got, want := parseIPv6PTR(name), referenceIPv6PTR(name); got != want {
			t.Fatalf("v6 %q: got %q, reference %q", name, got, want)
		}
	}

	// Deliberate tightening: shapes the old ParseIP-joining incidentally
	// admitted now refuse — no resolver emits them, and a refusal is an
	// ordinary miss downstream.
	for _, name := range []string{
		strings.Repeat("0.", 30) + "1" + ReverseDomainV6,         // 31 nibbles
		"ab." + strings.Repeat("0.", 29) + "1" + ReverseDomainV6, // multi-digit label
		"g." + strings.Repeat("0.", 30) + "1" + ReverseDomainV6,  // non-hex
	} {
		if got := parseIPv6PTR(name); got != "" {
			t.Fatalf("v6 %q: got %q, want refusal", name, got)
		}
	}
}

func TestParsePTRAllocs(t *testing.T) {
	v4 := "54.119.58.176" + ReverseDomainV4
	if n := testing.AllocsPerRun(200, func() {
		if parseIPv4PTR(v4) == "" {
			t.Fatal("refused")
		}
	}); n != 1 {
		t.Fatalf("v4 allocs = %v, want 1 (the result string)", n)
	}
}
