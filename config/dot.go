package config

import (
	"net"
	"strings"
)

// SplitDoTUpstream splits a DoT upstream, the part after "tls://", into the
// address to connect to and the name to authenticate the server as:
//
//	"192.0.2.1:853"                -> "192.0.2.1:853", ""
//	"192.0.2.1:853#dns.example.com" -> "192.0.2.1:853", "dns.example.com"
//
// Without a name the server's certificate must be valid for its IP address,
// as it always had to be. With one it must be valid for that name, which is
// also sent as SNI. The name is never resolved: the address says where to
// connect and the name only what must answer there, the IP address plus
// authentication domain name configuration of RFC 8310, section 7.1.
//
// ok is false when a name is given but is not one a certificate can be issued
// for. The address itself is left to the caller to check.
func SplitDoTUpstream(s string) (addr, authName string, ok bool) {
	addr, authName, found := strings.Cut(s, "#")
	if !found {
		return s, "", true
	}
	authName = strings.TrimSuffix(authName, ".")
	return addr, authName, validAuthName(authName)
}

// validAuthName reports whether name is a host name a certificate can be
// issued for: dot-separated labels of letters, digits and hyphens, none
// empty, none starting or ending with a hyphen, at most 63 bytes each and 253
// in all. An IP address is refused; it needs no name.
func validAuthName(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !isLDH(label[i]) {
				return false
			}
		}
	}
	return true
}

// isLDH reports whether c is a letter, a digit or a hyphen.
func isLDH(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-'
}
