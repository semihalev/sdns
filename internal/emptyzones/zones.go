// Package emptyzones holds the locally-served zones of RFC 6303, the list the
// AS112 middleware answers for by default.
//
// It lives apart from that middleware so the config package can check an
// operator's list against it. The middleware imports config, so config cannot
// import the middleware, and a second copy of the list written by hand would
// drift from this one, which is the mistake worth avoiding.
package emptyzones

import "github.com/miekg/dns"

// Default is every zone served locally unless the operator names their own.
// Keys are canonical: lowercase and rooted.
var Default = map[string]bool{
	"10.in-addr.arpa.":              true,
	"16.172.in-addr.arpa.":          true,
	"17.172.in-addr.arpa.":          true,
	"18.172.in-addr.arpa.":          true,
	"19.172.in-addr.arpa.":          true,
	"20.172.in-addr.arpa.":          true,
	"21.172.in-addr.arpa.":          true,
	"22.172.in-addr.arpa.":          true,
	"23.172.in-addr.arpa.":          true,
	"24.172.in-addr.arpa.":          true,
	"25.172.in-addr.arpa.":          true,
	"26.172.in-addr.arpa.":          true,
	"27.172.in-addr.arpa.":          true,
	"28.172.in-addr.arpa.":          true,
	"29.172.in-addr.arpa.":          true,
	"30.172.in-addr.arpa.":          true,
	"31.172.in-addr.arpa.":          true,
	"168.192.in-addr.arpa.":         true,
	"64.100.in-addr.arpa.":          true,
	"65.100.in-addr.arpa.":          true,
	"66.100.in-addr.arpa.":          true,
	"67.100.in-addr.arpa.":          true,
	"68.100.in-addr.arpa.":          true,
	"69.100.in-addr.arpa.":          true,
	"70.100.in-addr.arpa.":          true,
	"71.100.in-addr.arpa.":          true,
	"72.100.in-addr.arpa.":          true,
	"73.100.in-addr.arpa.":          true,
	"74.100.in-addr.arpa.":          true,
	"75.100.in-addr.arpa.":          true,
	"76.100.in-addr.arpa.":          true,
	"77.100.in-addr.arpa.":          true,
	"78.100.in-addr.arpa.":          true,
	"79.100.in-addr.arpa.":          true,
	"80.100.in-addr.arpa.":          true,
	"81.100.in-addr.arpa.":          true,
	"82.100.in-addr.arpa.":          true,
	"83.100.in-addr.arpa.":          true,
	"84.100.in-addr.arpa.":          true,
	"85.100.in-addr.arpa.":          true,
	"86.100.in-addr.arpa.":          true,
	"87.100.in-addr.arpa.":          true,
	"88.100.in-addr.arpa.":          true,
	"89.100.in-addr.arpa.":          true,
	"90.100.in-addr.arpa.":          true,
	"91.100.in-addr.arpa.":          true,
	"92.100.in-addr.arpa.":          true,
	"93.100.in-addr.arpa.":          true,
	"94.100.in-addr.arpa.":          true,
	"95.100.in-addr.arpa.":          true,
	"96.100.in-addr.arpa.":          true,
	"97.100.in-addr.arpa.":          true,
	"98.100.in-addr.arpa.":          true,
	"99.100.in-addr.arpa.":          true,
	"100.100.in-addr.arpa.":         true,
	"101.100.in-addr.arpa.":         true,
	"102.100.in-addr.arpa.":         true,
	"103.100.in-addr.arpa.":         true,
	"104.100.in-addr.arpa.":         true,
	"105.100.in-addr.arpa.":         true,
	"106.100.in-addr.arpa.":         true,
	"107.100.in-addr.arpa.":         true,
	"108.100.in-addr.arpa.":         true,
	"109.100.in-addr.arpa.":         true,
	"110.100.in-addr.arpa.":         true,
	"111.100.in-addr.arpa.":         true,
	"112.100.in-addr.arpa.":         true,
	"113.100.in-addr.arpa.":         true,
	"114.100.in-addr.arpa.":         true,
	"115.100.in-addr.arpa.":         true,
	"116.100.in-addr.arpa.":         true,
	"117.100.in-addr.arpa.":         true,
	"118.100.in-addr.arpa.":         true,
	"119.100.in-addr.arpa.":         true,
	"120.100.in-addr.arpa.":         true,
	"121.100.in-addr.arpa.":         true,
	"122.100.in-addr.arpa.":         true,
	"123.100.in-addr.arpa.":         true,
	"124.100.in-addr.arpa.":         true,
	"125.100.in-addr.arpa.":         true,
	"126.100.in-addr.arpa.":         true,
	"127.100.in-addr.arpa.":         true,
	"0.in-addr.arpa.":               true,
	"127.in-addr.arpa.":             true,
	"254.169.in-addr.arpa.":         true,
	"2.0.192.in-addr.arpa.":         true,
	"100.51.198.in-addr.arpa.":      true,
	"113.0.203.in-addr.arpa.":       true,
	"255.255.255.255.in-addr.arpa.": true,
	"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.": true,
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.": true,
	"d.f.ip6.arpa.":             true,
	"8.e.f.ip6.arpa.":           true,
	"9.e.f.ip6.arpa.":           true,
	"a.e.f.ip6.arpa.":           true,
	"b.e.f.ip6.arpa.":           true,
	"8.b.d.0.1.0.0.2.ip6.arpa.": true,
	"empty.as112.arpa.":         true,
	"home.arpa.":                true,
}

// Covers reports whether name, or any zone above it, is one of the zones
// above. The middleware walks the same suffixes when it decides which
// configured zones to keep: an entry it does not cover is dropped with a log
// line, and a list where every entry is dropped falls back to the whole set,
// so an operator who names a zone outside the tree quietly gets all of them.
func Covers(name string) bool {
	name = dns.CanonicalName(name)
	for off, end := 0, false; !end; off, end = dns.NextLabel(name, off) {
		if Default[name[off:]] {
			return true
		}
	}
	return false
}
