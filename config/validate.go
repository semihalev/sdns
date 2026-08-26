package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// Validate reports what is wrong with a loaded configuration.
//
// Every problem is collected and reported together. An operator fixing a
// config file wants the whole list, not one error per run — and a DNS server
// that refuses to start is a visible failure, where one that starts with a
// setting it silently ignored is not.
//
// The rules only reject what cannot be right: an address that does not parse,
// a value outside an enumerated set, a file that is not there. Anything this
// package cannot judge — whether an upstream answers, whether a certificate
// matches its key — belongs to the component that uses it.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	switch c.DNSSEC {
	case "", "on", "off":
	default:
		// Anything but "off" silently became "on", so a typo here turned
		// validation on when the operator meant to turn it off.
		add("dnssec = %q: must be \"on\" or \"off\"", c.DNSSEC)
	}

	// Exactly what startup accepts: the four levels, plus omission, which is
	// filled in as "info" before the logger sees it. Anything else stops the
	// server there, so a config test that disagreed would send the operator
	// to production with a file that cannot start. "crit" was documented for
	// years but never existed — the logger has no such level and startup
	// rejects it.
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		add("loglevel = %q: must be one of debug, info, warn, error", c.LogLevel)
	}

	for _, bind := range []struct{ key, value string }{
		{"bind", c.Bind},
		{"bindtls", c.BindTLS},
		{"binddoh", c.BindDOH},
		{"binddoq", c.BindDOQ},
	} {
		if bind.value == "" {
			continue
		}
		// An empty host is how every listener is told "all interfaces", so
		// only the port half is required.
		if _, port, err := net.SplitHostPort(bind.value); err != nil || port == "" {
			add("%s = %q: must be host:port", bind.key, bind.value)
		}
	}

	if c.BindTLS != "" || c.BindDOH != "" || c.BindDOQ != "" {
		if c.TLSCertificate == "" || c.TLSPrivateKey == "" {
			add("tlscertificate and tlsprivatekey are required when bindtls, binddoh or binddoq is set")
		} else {
			for _, f := range []struct{ key, path string }{
				{"tlscertificate", c.TLSCertificate},
				{"tlsprivatekey", c.TLSPrivateKey},
			} {
				if _, err := os.Stat(f.path); err != nil {
					add("%s = %q: %v", f.key, f.path, err)
				}
			}
		}
	}

	for _, ip := range []struct{ key, value string }{
		{"nullroute", c.Nullroute},
		{"nullroutev6", c.Nullroutev6},
	} {
		if ip.value != "" && net.ParseIP(ip.value) == nil {
			add("%s = %q: must be an IP address", ip.key, ip.value)
		}
	}

	for _, entry := range c.AccessList {
		// The access list is parsed with netip.ParsePrefix and nothing else,
		// so a bare address is dropped at startup. Accepting one here would
		// pass a file whose only entry is discarded — leaving an empty allow
		// set, which blocks every client.
		if !validCIDR(entry) {
			add("accesslist %q: must be a CIDR block, e.g. 192.0.2.0/24 or 192.0.2.1/32", entry)
		}
	}

	// The resolver takes IPv4 from rootservers and IPv6 from root6servers,
	// and silently drops anything in the wrong list. A misplaced address
	// therefore leaves a shorter root set than the operator wrote, or an
	// empty one.
	for _, list := range []struct {
		key    string
		values []string
		want   string // "4", "6", or "" for either
	}{
		{"rootservers", c.RootServers, "4"},
		{"root6servers", c.Root6Servers, "6"},
		{"fallbackservers", c.FallbackServers, ""},
	} {
		for _, addr := range list.values {
			host, port, err := net.SplitHostPort(addr)
			if err != nil || port == "" {
				add("%s %q: must be an IP address and port, e.g. 192.0.2.1:53", list.key, addr)
				continue
			}
			ip := net.ParseIP(host)
			if ip == nil {
				add("%s %q: must be an IP address and port, e.g. 192.0.2.1:53", list.key, addr)
				continue
			}
			is4 := ip.To4() != nil
			if (list.want == "4" && !is4) || (list.want == "6" && is4) {
				add("%s %q: must be an IPv%s address", list.key, addr, list.want)
			}
		}
	}

	for _, addr := range c.ForwarderServers {
		if err := validUpstream(addr); err != nil {
			add("forwarderservers %q: %v", addr, err)
		}
	}
	for i := range c.ForwardZones {
		zone := &c.ForwardZones[i]
		for _, addr := range zone.Servers {
			if err := validUpstream(addr); err != nil {
				add("forward_zone %q server %q: %v", zone.Name, addr, err)
			}
		}
	}

	for _, d := range []struct {
		key   string
		value Duration
	}{
		{"timeout", c.Timeout},
		{"querytimeout", c.QueryTimeout},
		{"roottcptimeout", c.RootTCPTimeout},
		{"tldtcptimeout", c.TLDTCPTimeout},
	} {
		if d.value.Duration < 0 {
			add("%s = %q: must not be negative", d.key, d.value.Duration)
		}
	}

	for _, n := range []struct {
		key   string
		value int
	}{
		{"cachesize", c.CacheSize},
		{"maxdepth", c.Maxdepth},
		{"ratelimit", c.RateLimit},
		{"clientratelimit", c.ClientRateLimit},
		{"maxconcurrentqueries", c.MaxConcurrentQueries},
	} {
		if n.value < 0 {
			add("%s = %d: must not be negative", n.key, n.value)
		}
	}

	c.validateTrustAndIdentity(add)
	c.validateNameLists(add)
	c.validateSubTables(add)

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

// validateTrustAndIdentity covers the settings that decide who this resolver
// trusts and what address it speaks from.
func (c *Config) validateTrustAndIdentity(add func(string, ...any)) {
	// Syntax alone does not make a usable root anchor, and every way of
	// getting it wrong fails somewhere the operator will not connect to
	// this file: a malformed record is fatal at resolver construction, a
	// record that is not a DNSKEY panics an unchecked type assertion during
	// verification, and a key that is merely not a root KSK leaves the
	// anchor set empty so every DNSSEC answer fails on unavailable anchors.
	anchors := 0
	for _, key := range c.RootKeys {
		rr, err := dns.NewRR(key)
		if err != nil {
			add("rootkeys %q: %v", key, err)
			continue
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			add("rootkeys %q: must be a DNSKEY record", key)
			continue
		}
		switch {
		case dns.CanonicalName(dnskey.Hdr.Name) != ".":
			add("rootkeys %q: must be owned by the root zone", key)
		case dnskey.Hdr.Class != dns.ClassINET:
			add("rootkeys %q: must be class IN", key)
		case dnskey.Protocol != 3:
			add("rootkeys %q: protocol must be 3 (RFC 4034 section 2.1.2)", key)
		case dnskey.Flags != 257:
			// Only key-signing keys enter the verification set.
			add("rootkeys %q: must be a key-signing key (flags 257), not %d", key, dnskey.Flags)
		default:
			anchors++
		}
	}
	if len(c.RootKeys) > 0 && anchors == 0 {
		add("rootkeys: none of the configured keys is a usable root trust anchor")
	}

	for _, out := range []struct {
		key    string
		values []string
		want4  bool
	}{
		{"outboundips", c.OutboundIPs, true},
		{"outboundip6s", c.OutboundIP6s, false},
	} {
		for _, addr := range out.values {
			ip := net.ParseIP(addr)
			if ip == nil {
				add("%s %q: must be an IP address", out.key, addr)
				continue
			}
			// Putting a v6 address in the v4 list is a mistake the resolver
			// cannot act on, and nothing downstream says so.
			if is4 := ip.To4() != nil; is4 != out.want4 {
				family := "IPv6"
				if out.want4 {
					family = "IPv4"
				}
				add("%s %q: must be an %s address", out.key, addr, family)
			}
		}
	}

	if c.API != "" {
		if _, port, err := net.SplitHostPort(c.API); err != nil || port == "" {
			add("api = %q: must be host:port", c.API)
		}
	}

	if c.HostsFile != "" {
		if _, err := os.Stat(c.HostsFile); err != nil {
			add("hostsfile = %q: %v", c.HostsFile, err)
		}
	}

	for _, addr := range c.HyperlocalRootSources {
		// Hostnames are expected here: the built-in sources are the root
		// servers' names.
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			add("hyperlocal_root_sources %q: must be host:port", addr)
		}
	}

	// The cache refuses anything above 90 and then disables prefetch
	// entirely, so 91-100 passed this test and silently turned the feature
	// off. The low end is clamped up to 10 rather than refused.
	if c.Prefetch > 90 {
		add("prefetch = %d: is a percentage of the original TTL and must not exceed 90", c.Prefetch)
	}

	if c.ReflexThreshold != 0 && (c.ReflexThreshold < 0 || c.ReflexThreshold > 1) {
		// Out of range is silently replaced by the default, so an operator
		// who wrote 42 believes they set a threshold they did not.
		add("reflexthreshold = %v: must be between 0 and 1", c.ReflexThreshold)
	}

	for name, plugin := range c.Plugins {
		if plugin.Path == "" {
			add("plugin %q has no path", name)
			continue
		}
		if _, err := os.Stat(plugin.Path); err != nil {
			add("plugin %q path %q: %v", name, plugin.Path, err)
		}
	}
}

// validateNameLists covers the settings that name zones or hosts.
func (c *Config) validateNameLists(add func(string, ...any)) {
	for _, list := range []struct {
		key      string
		values   []string
		wildcard bool
	}{
		{"blocklist", c.Blocklist, true},
		{"whitelist", c.Whitelist, true},
		{"emptyzones", c.EmptyZones, false},
	} {
		for _, entry := range list.values {
			name := entry
			// "*.example.com" blocks subdomains only; the star is the
			// blocklist's own syntax, not part of the name.
			if list.wildcard {
				name = strings.TrimPrefix(name, "*.")
			}
			if name == "" {
				add("%s entry %q is empty", list.key, entry)
				continue
			}
			if _, ok := dns.IsDomainName(name); !ok {
				add("%s %q: not a valid domain name", list.key, entry)
			}
		}
	}

	for _, u := range c.BlockLists {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" || parsed.Scheme == "" {
			add("blocklists %q: must be a URL", u)
		}
	}
}

// validateSubTables covers the settings that live under their own headings.
func (c *Config) validateSubTables(add func(string, ...any)) {
	for i := range c.Views {
		view := &c.Views[i]
		label := view.Zone
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if view.Zone != "" {
			if _, ok := dns.IsDomainName(view.Zone); !ok {
				add("view %s: zone is not a valid domain name", label)
			}
		}
		for _, network := range view.Networks {
			if !validCIDR(network) {
				add("view %s network %q: must be a CIDR block", label, network)
			}
		}
		for _, answer := range view.Answers {
			if _, err := dns.NewRR(answer); err != nil {
				add("view %s answer %q: %v", label, answer, err)
			}
		}
	}

	// These are the rules middleware/dns64 applies at startup. A prefix that
	// only looks like IPv6 is dropped there, and if it was the only one the
	// resolver falls back to 64:ff9b::/96 — so a config test that accepted
	// it would report success while traffic went to a different NAT64
	// prefix than the file names.
	//
	// The family test is the mask length, not To4(): an IPv4-mapped range
	// like ::ffff:0:0/96 has a non-nil To4() and is a legal Pref64 input.
	validPrefixBits := map[int]bool{32: true, 40: true, 48: true, 56: true, 64: true, 96: true}
	for _, prefix := range c.DNS64.Prefixes {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			add("dns64 prefix %q: must be a CIDR block", prefix)
			continue
		}
		if len(network.Mask) != net.IPv6len {
			add("dns64 prefix %q: is IPv4, want IPv6", prefix)
			continue
		}
		bits, _ := network.Mask.Size()
		if !validPrefixBits[bits] {
			add("dns64 prefix %q: length /%d invalid; must be /32, /40, /48, /56, /64, or /96", prefix, bits)
			continue
		}
		// RFC 6052 §2.2 reserves byte 8; at /96 the operator's prefix
		// already covers it.
		if bits == 96 && len(network.IP) >= 9 && network.IP[8] != 0 {
			add("dns64 prefix %q: byte 8 must be zero (RFC 6052 section 2.2 reserved)", prefix)
		}
	}
	for _, list := range []struct {
		key    string
		values []string
	}{
		{"dns64 client_networks", c.DNS64.ClientNetworks},
		{"dns64 exclude_a_networks", c.DNS64.ExcludeANetworks},
		{"dns64 exclude_aaaa_networks", c.DNS64.ExcludeAAAANetworks},
		{"ecs client_networks", c.ECS.ClientNetworks},
	} {
		for _, network := range list.values {
			if !validCIDR(network) {
				add("%s %q: must be a CIDR block", list.key, network)
			}
		}
	}
	for _, zone := range c.DNS64.ExcludeZones {
		if _, ok := dns.IsDomainName(zone); !ok {
			add("dns64 exclude_zones %q: not a valid domain name", zone)
		}
	}

	for _, bits := range []struct {
		key   string
		value uint8
		max   uint8
	}{
		{"ecs forward_v4", c.ECS.ForwardV4Max, 32},
		{"ecs min_scope_v4", c.ECS.MinScopeV4, 32},
		{"ecs forward_v6", c.ECS.ForwardV6Max, 128},
		{"ecs min_scope_v6", c.ECS.MinScopeV6, 128},
	} {
		if bits.value > bits.max {
			add("%s = %d: must not exceed %d", bits.key, bits.value, bits.max)
		}
	}
}

func validCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// validIPPort reports whether addr is an IP literal with a port. Authority and
// fallback servers are dialled directly, so a hostname there would need a
// resolver this one may not have yet.
func validIPPort(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return false
	}
	return net.ParseIP(host) != nil
}

// validUpstream reports whether addr is one of the three forms a forwarder
// upstream may take. It mirrors what middleware/forwarder accepts, so a config
// that passes here is one the forwarder can actually use.
func validUpstream(addr string) error {
	switch {
	case strings.HasPrefix(addr, "https://"):
		// DoH may name a host: it is bootstrapped once at startup.
		u, err := url.Parse(addr)
		if err != nil || u.Host == "" {
			return fmt.Errorf("not a usable DoH URL")
		}
		return nil
	case strings.HasPrefix(addr, "tls://"):
		if !validIPPort(strings.TrimPrefix(addr, "tls://")) {
			return fmt.Errorf("DoT needs an IP address and port, e.g. tls://192.0.2.1:853")
		}
		return nil
	default:
		if !validIPPort(addr) {
			return fmt.Errorf("must be an IP address and port, a tls:// address, or an https:// URL")
		}
		return nil
	}
}
