package dns64

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// validPrefixBits is the set of IPv6 prefix lengths permitted for
// IPv4-embedded IPv6 addresses by RFC 6052 §2.2. Any other length is
// rejected at config-load time.
var validPrefixBits = map[int]bool{
	32: true,
	40: true,
	48: true,
	56: true,
	64: true,
	96: true,
}

// wellKnownPrefix is the "Well-Known Prefix" 64:ff9b::/96 from RFC
// 6052 §2.1. Translation through this prefix is restricted: per RFC
// 6052 §3.1 and RFC 6147 §5.1.4, IPv4 addresses in special-use
// ranges (RFC 5735 / RFC 6890) MUST NOT be embedded into the
// well-known prefix because the resulting IPv6 address would not be
// globally reachable.
var wellKnownPrefix = mustCIDR("64:ff9b::/96")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// validatePrefix verifies prefix is a valid Pref64::/n per RFC 6052
// §2.2. Returns an error with a descriptive message on rejection.
func validatePrefix(p *net.IPNet) error {
	if p == nil {
		return fmt.Errorf("dns64: nil prefix")
	}
	// Use mask length, not IP.To4(), to distinguish IPv4 from
	// IPv6 inputs — IPv4-mapped IPv6 ranges like ::ffff:0:0/96
	// have a non-nil To4() but are still legal Pref64 inputs.
	if len(p.Mask) != net.IPv6len {
		return fmt.Errorf("dns64: prefix %s is IPv4, want IPv6", p.String())
	}
	bits, _ := p.Mask.Size()
	if !validPrefixBits[bits] {
		return fmt.Errorf("dns64: prefix length /%d invalid; must be /32, /40, /48, /56, /64, or /96", bits)
	}
	// Per RFC 6052 §2.2 byte 8 (bits 64-71) MUST be zero in the
	// resulting address. For /96 the operator's prefix already
	// covers byte 8, so reject prefixes with a non-zero byte 8 up
	// front rather than silently producing a non-conformant result.
	if bits == 96 && len(p.IP) >= 9 && p.IP[8] != 0 {
		return fmt.Errorf("dns64: /96 prefix %s has non-zero byte 8 (RFC 6052 §2.2 reserved)", p.String())
	}
	return nil
}

// embedIPv4 returns the IPv4-embedded IPv6 address built from prefix
// and v4 per RFC 6052 §2.2. prefix must satisfy validatePrefix; v4
// must be a 4-byte IPv4 address (callers should pass v4.To4()).
//
// The v4 octets are interleaved around byte 8 (the "u" octet) for
// /32, /40, /48, /56, /64 prefixes. Byte 8 itself is always written
// as zero, regardless of any value the operator may have placed
// there in the configured prefix — RFC 6052 §2.2 reserves it.
//
// Trailing octets beyond the embedded v4 are zeroed (the "suffix"
// in the RFC's terminology). Suffix is reserved for future use and
// must be transmitted as zero.
func embedIPv4(prefix *net.IPNet, v4 net.IP) net.IP {
	bits, _ := prefix.Mask.Size()
	out := make(net.IP, net.IPv6len)
	// Copy the prefix bytes that are fully covered by the mask.
	// For /32 prefix this is bytes 0-3, for /96 it is bytes 0-11.
	prefixBytes := bits / 8
	copy(out[:prefixBytes], prefix.IP[:prefixBytes])

	// v4 must be exactly 4 bytes here.
	switch bits {
	case 32:
		// v4 at bytes 4-7; byte 8 = 0; suffix zero.
		copy(out[4:8], v4)
	case 40:
		// v4 high 24 bits at bytes 5-7; byte 8 = 0; v4 low 8 bits at byte 9.
		copy(out[5:8], v4[:3])
		out[9] = v4[3]
	case 48:
		// v4 high 16 bits at bytes 6-7; byte 8 = 0; v4 low 16 bits at bytes 9-10.
		copy(out[6:8], v4[:2])
		copy(out[9:11], v4[2:])
	case 56:
		// v4 high 8 bits at byte 7; byte 8 = 0; v4 low 24 bits at bytes 9-11.
		out[7] = v4[0]
		copy(out[9:12], v4[1:])
	case 64:
		// byte 8 = 0; v4 at bytes 9-12.
		copy(out[9:13], v4)
	case 96:
		// v4 at bytes 12-15.
		copy(out[12:16], v4)
	}
	return out
}

// excludedV4 reports whether v4 falls in any of the "do not
// translate" ranges. RFC 6147 §5.1.4 directs the implementation to
// skip synthesis for IPv4 addresses that would not be globally
// reachable when expressed as 64:ff9b::/96. The caller decides
// whether to apply the check (only the well-known prefix is bound
// by §5.1.4; operator-chosen network-specific prefixes have their
// own scope and may legitimately translate private addresses).
func excludedV4(v4 net.IP, exclusions []*net.IPNet) bool {
	if len(exclusions) == 0 {
		return false
	}
	for _, n := range exclusions {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// isWellKnownPrefix reports whether p is exactly 64:ff9b::/96. RFC
// 6147 §5.1.4 exclusions apply to this prefix only.
func isWellKnownPrefix(p *net.IPNet) bool {
	if p == nil {
		return false
	}
	pBits, _ := p.Mask.Size()
	wkBits, _ := wellKnownPrefix.Mask.Size()
	if pBits != wkBits {
		return false
	}
	return p.IP.Equal(wellKnownPrefix.IP)
}

// synthesizeAAAA builds a synthetic AAAA RR for qname from the given
// A record using prefix. The synthesised record uses ttl as its TTL
// (caller selects per RFC 6147 §5.1.7 — the lower of the original
// AAAA negative TTL and the A TTL). qname is used as the owner so
// the record matches the client's question regardless of any CNAME
// chain that landed on the A record's owner.
func synthesizeAAAA(qname string, a *dns.A, prefix *net.IPNet, ttl uint32) *dns.AAAA {
	v4 := a.A.To4()
	if v4 == nil {
		return nil
	}
	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		AAAA: embedIPv4(prefix, v4),
	}
}

// extractIPv4 is the inverse of embedIPv4. It returns the IPv4
// address embedded in addr under prefix, plus true on success.
// Returns false when prefix doesn't actually contain addr, when
// the reserved "u" octet (byte 8) is non-zero for a /32../64
// prefix, or when the suffix bits beyond the embedded v4 are
// non-zero (RFC 6052 §2.2 reserves them as MUST-be-zero).
//
// The strict zero-bit checks matter for PTR translation: a
// non-conformant address inside the prefix range may not actually
// be a translated address, so refusing to extract avoids
// returning a confusing CNAME for unrelated traffic.
func extractIPv4(prefix *net.IPNet, addr net.IP) (net.IP, bool) {
	if !prefix.Contains(addr) {
		return nil, false
	}
	bits, _ := prefix.Mask.Size()
	if !validPrefixBits[bits] {
		return nil, false
	}
	a := addr.To16()
	if a == nil {
		return nil, false
	}
	out := make(net.IP, net.IPv4len)
	switch bits {
	case 32:
		copy(out, a[4:8])
		if !bytesAllZero(a[8:]) {
			return nil, false
		}
	case 40:
		copy(out[:3], a[5:8])
		if a[8] != 0 {
			return nil, false
		}
		out[3] = a[9]
		if !bytesAllZero(a[10:]) {
			return nil, false
		}
	case 48:
		copy(out[:2], a[6:8])
		if a[8] != 0 {
			return nil, false
		}
		copy(out[2:], a[9:11])
		if !bytesAllZero(a[11:]) {
			return nil, false
		}
	case 56:
		out[0] = a[7]
		if a[8] != 0 {
			return nil, false
		}
		copy(out[1:], a[9:12])
		if !bytesAllZero(a[12:]) {
			return nil, false
		}
	case 64:
		if a[8] != 0 {
			return nil, false
		}
		copy(out, a[9:13])
		if !bytesAllZero(a[13:]) {
			return nil, false
		}
	case 96:
		copy(out, a[12:16])
	}
	return out, true
}

func bytesAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// parseIP6ArpaName decodes an ip6.arpa.-suffixed PTR query name
// into its 16-byte IPv6 address. Returns false when the name
// isn't well-formed (wrong number of labels, non-hex nibble,
// labels longer than one character).
func parseIP6ArpaName(qname string) (net.IP, bool) {
	q := strings.ToLower(qname)
	q = strings.TrimSuffix(q, ".")
	if !strings.HasSuffix(q, ".ip6.arpa") {
		return nil, false
	}
	head := strings.TrimSuffix(q, ".ip6.arpa")
	parts := strings.Split(head, ".")
	if len(parts) != 32 {
		return nil, false
	}
	out := make(net.IP, net.IPv6len)
	for i, label := range parts {
		if len(label) != 1 {
			return nil, false
		}
		nib, ok := hexNibble(label[0])
		if !ok {
			return nil, false
		}
		nibbleIdx := 31 - i
		byteIdx := nibbleIdx / 2
		if nibbleIdx%2 == 0 {
			out[byteIdx] |= nib << 4
		} else {
			out[byteIdx] |= nib
		}
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// inAddrArpa returns the in-addr.arpa.-suffixed reverse name for
// the given IPv4 address. Used to redirect ip6.arpa PTR queries
// that fall under a configured Pref64 to their IPv4 reverse-zone
// counterpart per RFC 6147 §5.3.1.
func inAddrArpa(v4 net.IP) string {
	v4 = v4.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
}
