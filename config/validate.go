package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
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

	switch c.LogLevel {
	case "", "crit", "debug", "info", "warn", "error":
	default:
		add("loglevel = %q: must be one of crit, debug, info, warn, error", c.LogLevel)
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

	for i, entry := range c.AccessList {
		if entry == "" {
			add("accesslist entry %d is empty", i+1)
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}
		if net.ParseIP(entry) == nil {
			add("accesslist %q: must be an IP address or CIDR block", entry)
		}
	}

	for _, list := range []struct {
		key    string
		values []string
	}{
		{"rootservers", c.RootServers},
		{"root6servers", c.Root6Servers},
		{"fallbackservers", c.FallbackServers},
	} {
		for _, addr := range list.values {
			if !validIPPort(addr) {
				add("%s %q: must be an IP address and port, e.g. 192.0.2.1:53", list.key, addr)
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

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
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
