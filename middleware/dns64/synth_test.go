package dns64

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func parseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

// TestEmbedIPv4_RFC6052Vectors covers every permitted prefix length
// using the test vectors illustrated in RFC 6052 §2.4. v4 is
// 192.0.2.33 throughout, so every output can be cross-checked
// against the table in the RFC.
func TestEmbedIPv4_RFC6052Vectors(t *testing.T) {
	v4 := net.ParseIP("192.0.2.33").To4()
	cases := []struct {
		name   string
		prefix string
		want   string
	}{
		{"/32", "2001:db8::/32", "2001:db8:c000:221::"},
		{"/40", "2001:db8:100::/40", "2001:db8:1c0:2:21::"},
		{"/48", "2001:db8:122::/48", "2001:db8:122:c000:2:2100::"},
		{"/56", "2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"},
		{"/64", "2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"},
		{"/96", "2001:db8:122:344::/96", "2001:db8:122:344::c000:221"},
		{"/96 well-known", "64:ff9b::/96", "64:ff9b::c000:221"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := embedIPv4(parseCIDR(t, tc.prefix), v4)
			want := net.ParseIP(tc.want)
			if !got.Equal(want) {
				t.Fatalf("embedIPv4(%s, 192.0.2.33) = %s, want %s", tc.prefix, got, want)
			}
		})
	}
}

// TestEmbedIPv4_ZeroesUOctet pins the RFC 6052 §2.2 invariant that
// byte 8 of the synthesised address is always zero, regardless of
// whatever (non-/96) prefix the operator configured. We don't allow
// non-zero byte 8 in /96 prefixes (validatePrefix rejects them);
// for /32-/64 the prefix mask doesn't even reach byte 8, so this
// test exercises the embed function's own zero-write behaviour.
func TestEmbedIPv4_ZeroesUOctet(t *testing.T) {
	v4 := net.ParseIP("203.0.113.7").To4()
	for _, p := range []string{
		"2001:db8::/32",
		"2001:db8:100::/40",
		"2001:db8:122::/48",
		"2001:db8:122:300::/56",
		"2001:db8:122:344::/64",
	} {
		got := embedIPv4(parseCIDR(t, p), v4)
		if got[8] != 0 {
			t.Errorf("prefix %s: byte 8 = %#x, want 0", p, got[8])
		}
	}
}

func TestValidatePrefix(t *testing.T) {
	cases := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{"valid /32", "2001:db8::/32", false},
		{"valid /96", "2001:db8::/96", false},
		{"valid well-known /96", "64:ff9b::/96", false},
		{"invalid /48 +1", "2001:db8::/49", true},
		{"invalid /128", "2001:db8::1/128", true},
		{"invalid /0", "::/0", true},
		{"ipv4 prefix", "192.0.2.0/24", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePrefix(parseCIDR(t, tc.prefix))
			if tc.wantErr && err == nil {
				t.Fatalf("validatePrefix(%s) = nil, want error", tc.prefix)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validatePrefix(%s) = %v, want nil", tc.prefix, err)
			}
		})
	}
}

func TestValidatePrefix_NonZeroByte8For96(t *testing.T) {
	// Byte 8 (bits 64-71) is the 5th hextet's high byte, so we need a
	// /96 prefix whose 5th hextet is non-zero. 2001:db8:0:0:ff00::/96
	// gives byte 8 = 0xff.
	_, p, err := net.ParseCIDR("2001:db8:0:0:ff00::/96")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.IP[8] == 0 {
		t.Fatalf("test setup error: byte 8 must be non-zero, got %#x in %s", p.IP[8], p.IP)
	}
	if err := validatePrefix(p); err == nil {
		t.Fatalf("validatePrefix accepted /96 with non-zero byte 8")
	}
}

func TestExcludedV4(t *testing.T) {
	exclusions := []*net.IPNet{
		parseCIDR(t, "10.0.0.0/8"),
		parseCIDR(t, "192.168.0.0/16"),
		parseCIDR(t, "127.0.0.0/8"),
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.42.7", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"203.0.113.10", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := excludedV4(net.ParseIP(tc.ip).To4(), exclusions)
			if got != tc.want {
				t.Fatalf("excludedV4(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestExcludedV4_EmptyList(t *testing.T) {
	if excludedV4(net.ParseIP("10.0.0.1").To4(), nil) {
		t.Fatalf("empty exclusions should never exclude")
	}
}

func TestIsWellKnownPrefix(t *testing.T) {
	if !isWellKnownPrefix(parseCIDR(t, "64:ff9b::/96")) {
		t.Fatalf("64:ff9b::/96 should be the well-known prefix")
	}
	if isWellKnownPrefix(parseCIDR(t, "2001:db8::/96")) {
		t.Fatalf("2001:db8::/96 is not the well-known prefix")
	}
	if isWellKnownPrefix(parseCIDR(t, "64:ff9b::/64")) {
		t.Fatalf("/64 prefix length cannot match well-known /96")
	}
}

func TestSynthesizeAAAA(t *testing.T) {
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "alias.example.org.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    600,
		},
		A: net.ParseIP("192.0.2.33"),
	}
	prefix := parseCIDR(t, "64:ff9b::/96")
	got := synthesizeAAAA("client.example.com.", a, prefix, 300)
	if got == nil {
		t.Fatalf("synthesizeAAAA returned nil")
	}
	if got.Hdr.Name != "client.example.com." {
		t.Errorf("owner = %s, want client.example.com.", got.Hdr.Name)
	}
	if got.Hdr.Ttl != 300 {
		t.Errorf("TTL = %d, want 300 (the explicitly clamped value)", got.Hdr.Ttl)
	}
	if !got.AAAA.Equal(net.ParseIP("64:ff9b::c000:221")) {
		t.Errorf("AAAA = %s, want 64:ff9b::c000:221", got.AAAA)
	}
}

func TestSynthesizeAAAA_NilForNonV4(t *testing.T) {
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("::1"),
	}
	if synthesizeAAAA("x.", a, parseCIDR(t, "64:ff9b::/96"), 60) != nil {
		t.Fatalf("synthesizeAAAA should return nil for non-IPv4 address")
	}
}

// TestExtractIPv4_RoundTrip pins that embedIPv4 ↔ extractIPv4 are
// consistent across every permitted prefix length.
func TestExtractIPv4_RoundTrip(t *testing.T) {
	v4 := net.ParseIP("192.0.2.33").To4()
	for _, prefix := range []string{
		"2001:db8::/32",
		"2001:db8:100::/40",
		"2001:db8:122::/48",
		"2001:db8:122:300::/56",
		"2001:db8:122:344::/64",
		"2001:db8:122:344::/96",
		"64:ff9b::/96",
	} {
		t.Run(prefix, func(t *testing.T) {
			p := parseCIDR(t, prefix)
			embedded := embedIPv4(p, v4)
			got, ok := extractIPv4(p, embedded)
			if !ok {
				t.Fatalf("extractIPv4 returned !ok for %s + %s", prefix, embedded)
			}
			if !got.Equal(v4) {
				t.Fatalf("round-trip mismatch: got %s, want %s", got, v4)
			}
		})
	}
}

func TestExtractIPv4_RejectsNonZeroSuffix(t *testing.T) {
	prefix := parseCIDR(t, "2001:db8:122:344::/64")
	v4 := net.ParseIP("192.0.2.33").To4()
	addr := embedIPv4(prefix, v4)
	addr[15] = 0xff // suffix byte must be zero per RFC 6052 §2.2
	if _, ok := extractIPv4(prefix, addr); ok {
		t.Fatalf("extractIPv4 must refuse addresses with non-zero suffix")
	}
}

func TestExtractIPv4_RejectsNonZeroUOctet(t *testing.T) {
	prefix := parseCIDR(t, "2001:db8::/32")
	v4 := net.ParseIP("192.0.2.33").To4()
	addr := embedIPv4(prefix, v4)
	addr[8] = 0xff // u octet must be zero
	if _, ok := extractIPv4(prefix, addr); ok {
		t.Fatalf("extractIPv4 must refuse addresses with non-zero u octet")
	}
}

func TestExtractIPv4_AddressOutsidePrefix(t *testing.T) {
	prefix := parseCIDR(t, "64:ff9b::/96")
	if _, ok := extractIPv4(prefix, net.ParseIP("2001:db8::1")); ok {
		t.Fatalf("extractIPv4 must return false for addresses outside the prefix")
	}
}

func TestParseIP6ArpaName_RoundTrip(t *testing.T) {
	// 192.0.2.33 embedded in 64:ff9b::/96 = 64:ff9b::c000:221.
	qname := "1.2.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa."
	addr, ok := parseIP6ArpaName(qname)
	if !ok {
		t.Fatalf("parseIP6ArpaName(%q) returned !ok", qname)
	}
	if !addr.Equal(net.ParseIP("64:ff9b::c000:221")) {
		t.Fatalf("parsed address = %s, want 64:ff9b::c000:221", addr)
	}
}

func TestParseIP6ArpaName_BadShape(t *testing.T) {
	cases := []string{
		"foo.bar.",                               // wrong suffix
		"1.2.3.ip6.arpa.",                        // too few labels
		strings.Repeat("0.", 32) + "z.ip6.arpa.", // 33 labels
		"x.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",  // bad nibble
		"00.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", // multi-char label
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			if _, ok := parseIP6ArpaName(q); ok {
				t.Fatalf("parseIP6ArpaName accepted malformed %q", q)
			}
		})
	}
}

func TestInAddrArpa(t *testing.T) {
	got := inAddrArpa(net.ParseIP("192.0.2.33"))
	if got != "33.2.0.192.in-addr.arpa." {
		t.Fatalf("inAddrArpa(192.0.2.33) = %q, want 33.2.0.192.in-addr.arpa.", got)
	}
	if inAddrArpa(net.ParseIP("::1")) != "" {
		t.Fatalf("inAddrArpa must return \"\" for non-IPv4 input")
	}
}
