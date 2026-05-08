package dns64

import (
	"net"
	"strings"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/zlog/v2"
)

// compiled holds the runtime form of cfg.DNS64 — prefixes and CIDR
// lists as net.IPNet structs, the exclude-zone list canonicalised
// to lower-case fully-qualified form, and the active prefix
// pre-selected. compileConfig returns nil when DNS64 is disabled
// or has no usable configuration so the constructor can short-
// circuit to typed-nil.
type compiled struct {
	prefixes       []compiledPrefix
	clientNetworks []*net.IPNet
	excludeZones   []string
	excludeAv4     []*net.IPNet
	excludeAAAA    []*net.IPNet
}

// compiledPrefix is one Pref64 entry pre-validated and tagged with
// whether it is the IANA Well-Known Prefix. RFC 6147 §5.1.4 ties
// the IPv4 exclusion list to that prefix only, so the bool is the
// per-prefix gate on shouldExcludeA.
type compiledPrefix struct {
	net       *net.IPNet
	wellKnown bool
}

// hasWellKnown reports whether any configured prefix is the
// well-known one. Used to decide whether to parse exclude_a_networks
// (operator-only prefixes ignore that list, so when no well-known
// is present we can skip the parse work entirely).
func (c *compiled) hasWellKnown() bool {
	for _, p := range c.prefixes {
		if p.wellKnown {
			return true
		}
	}
	return false
}

// defaultExcludeAAAA is the RFC 6147 §5.1.4 baseline: filter
// IPv4-mapped IPv6 addresses out of upstream AAAA responses so
// DNS64 doesn't pass non-routable answers through to the client.
// Used when the operator omits exclude_aaaa_networks entirely;
// passing an explicit empty list keeps the filter empty.
var defaultExcludeAAAA = []*net.IPNet{mustCIDR("::ffff:0:0/96")}

// defaultExcludeAv4 is the runtime baseline for
// exclude_a_networks when the well-known prefix 64:ff9b::/96 is
// active and the operator hasn't supplied a list. RFC 6052 §3.1
// forbids translating non-globally-reachable IPv4 ranges through
// the WKP; this list mirrors the IANA Special-Purpose Address
// Registry entries that fall in that category. Operators who
// declare exclude_a_networks = [] explicitly opt out.
var defaultExcludeAv4 = []*net.IPNet{
	mustCIDR("0.0.0.0/8"),
	mustCIDR("10.0.0.0/8"),
	mustCIDR("100.64.0.0/10"),
	mustCIDR("127.0.0.0/8"),
	mustCIDR("169.254.0.0/16"),
	mustCIDR("172.16.0.0/12"),
	mustCIDR("192.0.0.0/24"),
	mustCIDR("192.0.2.0/24"),
	// 192.88.99.0/24 — 6to4 anycast relay range, deprecated by
	// RFC 7526. The IANA Special-Purpose Address Registry marks
	// 192.88.99.2/32 as Globally Reachable: False; we cover the
	// whole /24 to stay aligned with RFC 6052 §3.1.
	mustCIDR("192.88.99.0/24"),
	mustCIDR("192.168.0.0/16"),
	mustCIDR("198.18.0.0/15"),
	mustCIDR("198.51.100.0/24"),
	mustCIDR("203.0.113.0/24"),
	mustCIDR("224.0.0.0/4"),
	mustCIDR("240.0.0.0/4"),
	mustCIDR("255.255.255.255/32"),
}

// compileConfig parses cfg.DNS64 into a runtime-friendly form. Bad
// entries are logged and skipped (matching the views / accesslist
// pattern), so a single typo in one prefix doesn't disable the
// middleware. Returns nil when DNS64 is not enabled or has no
// usable prefix — New translates that into a typed-nil Handler so
// the registry skips the middleware entirely.
func compileConfig(cfg *config.Config) *compiled {
	c := cfg.DNS64
	if !c.Enabled {
		return nil
	}

	out := &compiled{}
	for _, raw := range c.Prefixes {
		_, p, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			zlog.Error("DNS64 prefix parse failed", "prefix", raw, "error", err.Error())
			continue
		}
		if err := validatePrefix(p); err != nil {
			zlog.Error("DNS64 prefix invalid", "prefix", raw, "error", err.Error())
			continue
		}
		out.prefixes = append(out.prefixes, compiledPrefix{
			net:       p,
			wellKnown: isWellKnownPrefix(p),
		})
	}
	if len(out.prefixes) == 0 {
		// RFC 6147 §5.2: when no usable prefix is configured the
		// default is the IANA Well-Known Prefix 64:ff9b::/96.
		// We arrive here either because the operator omitted
		// the field entirely or every entry failed validation —
		// either way, the default keeps DNS64 functional rather
		// than silently disabling.
		zlog.Info("DNS64 enabled with no configured prefix; defaulting to 64:ff9b::/96 per RFC 6147 §5.2")
		out.prefixes = []compiledPrefix{{net: wellKnownPrefix, wellKnown: true}}
	}

	for _, raw := range c.ClientNetworks {
		_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			zlog.Error("DNS64 client network parse failed", "cidr", raw, "error", err.Error())
			continue
		}
		out.clientNetworks = append(out.clientNetworks, n)
	}

	for _, z := range c.ExcludeZones {
		z = strings.TrimSpace(strings.ToLower(z))
		if z == "" {
			continue
		}
		if !strings.HasSuffix(z, ".") {
			z += "."
		}
		out.excludeZones = append(out.excludeZones, z)
	}

	// Exclude-A networks are only consulted under the well-known
	// prefix (RFC 6147 §5.1.4 / RFC 6052 §3.1). When that prefix
	// is active we apply a runtime default if the field was
	// omitted (nil) — the operator can opt out by declaring an
	// explicit empty list. When no configured prefix is the
	// well-known one, skip the parse entirely.
	if out.hasWellKnown() {
		if c.ExcludeANetworks == nil {
			out.excludeAv4 = defaultExcludeAv4
		} else {
			for _, raw := range c.ExcludeANetworks {
				_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
				if err != nil {
					zlog.Error("DNS64 exclude-a-network parse failed", "cidr", raw, "error", err.Error())
					continue
				}
				if len(n.Mask) != net.IPv4len {
					zlog.Error("DNS64 exclude-a-network is not IPv4", "cidr", raw)
					continue
				}
				out.excludeAv4 = append(out.excludeAv4, n)
			}
		}
	}

	// Exclude-AAAA networks (RFC 6147 §5.1.4): apply the default
	// only when the operator left the field unset (nil). A
	// declared-but-empty list opts out of filtering deliberately
	// — the TOML decoder distinguishes nil from a zero-length
	// slice for us.
	if c.ExcludeAAAANetworks == nil {
		out.excludeAAAA = defaultExcludeAAAA
	} else {
		for _, raw := range c.ExcludeAAAANetworks {
			_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
			if err != nil {
				zlog.Error("DNS64 exclude-aaaa-network parse failed", "cidr", raw, "error", err.Error())
				continue
			}
			// net.ParseCIDR returns a 4-byte mask for IPv4 inputs
			// and a 16-byte mask for IPv6 — IP.To4() is the wrong
			// discriminator because IPv4-mapped IPv6 ranges like
			// ::ffff:0:0/96 are themselves 16-byte addresses with
			// a non-nil To4(). Use the mask length so the
			// well-known IPv4-mapped exclusion default is
			// accepted when explicitly listed.
			if len(n.Mask) != net.IPv6len {
				zlog.Error("DNS64 exclude-aaaa-network is IPv4, want IPv6", "cidr", raw)
				continue
			}
			out.excludeAAAA = append(out.excludeAAAA, n)
		}
	}

	return out
}

// shouldExcludeAAAA reports whether ip falls in any of the
// configured exclude-AAAA prefixes. RFC 6147 §5.1.4 — applied
// before deciding whether the upstream answer counts as
// non-empty.
func (c *compiled) shouldExcludeAAAA(ip net.IP) bool {
	if len(c.excludeAAAA) == 0 {
		return false
	}
	for _, n := range c.excludeAAAA {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientEligible reports whether ip should receive DNS64 synthesis.
// An empty client-network list is treated as "all clients" — same
// shape as accesslist's default.
func (c *compiled) clientEligible(ip net.IP) bool {
	if len(c.clientNetworks) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range c.clientNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// zoneExcluded reports whether qname (canonical, lower-case, FQDN)
// suffix-matches one of the exclude-zone entries. The zone "." is
// not allowed in the config (it would disable the middleware), so
// the FQDN root never appears here. Match must occur on a label
// boundary: "example.org." matches "example.org." and
// "host.example.org.", but NOT "badexample.org.".
func (c *compiled) zoneExcluded(qname string) bool {
	if len(c.excludeZones) == 0 {
		return false
	}
	for _, z := range c.excludeZones {
		if qname == z {
			return true
		}
		// z always ends with "." (FQDN'd at compile time), so
		// "."+z forces the label boundary check — no fragment
		// can match a longer label here.
		if strings.HasSuffix(qname, "."+z) {
			return true
		}
	}
	return false
}

// shouldExcludeAOnPrefix reports whether v4 should be skipped per
// RFC 6147 §5.1.4 when synthesising into the given prefix. The
// IPv4 exclusion list is bound to the well-known prefix only;
// operator-chosen prefixes always synthesise.
func (c *compiled) shouldExcludeAOnPrefix(v4 net.IP, p compiledPrefix) bool {
	if !p.wellKnown {
		return false
	}
	return excludedV4(v4, c.excludeAv4)
}
