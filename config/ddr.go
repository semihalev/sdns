package config

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// DDRTarget is the name DDR advertises as the SVCB TargetName: ddr.name when
// set, otherwise the first DNS name in tlscertificate's subjectAltName. The
// middleware and the config gate both call it, so sdns -t rejects exactly
// the files the running server could not advertise from.
//
// RFC 9462 §4 forbids "." and resolver.arpa itself as the TargetName: the
// client needs a name it can reach and check the certificate against.
func (c *Config) DDRTarget() (string, error) {
	name := strings.TrimSpace(c.DDR.Name)
	if name == "" {
		var err error
		if name, err = firstCertDNSName(c.TLSCertificate); err != nil {
			return "", err
		}
	}
	name = strings.ToLower(dns.Fqdn(name))
	if _, ok := dns.IsDomainName(name); !ok || name == "." {
		return "", fmt.Errorf("%q is not a domain name", name)
	}
	if dns.IsSubDomain("resolver.arpa.", name) {
		return "", fmt.Errorf("%q is under resolver.arpa, which clients cannot reach", name)
	}
	return name, nil
}

func firstCertDNSName(path string) (string, error) {
	if path == "" {
		return "", errors.New("name is empty and there is no tlscertificate to take it from")
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304 - the operator's own certificate path
	if err != nil {
		return "", err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return "", fmt.Errorf("%s holds no certificate", path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("%s: %v", path, err)
		}
		// The leaf is the first certificate; the rest of the chain names
		// the issuers, not this server.
		if len(cert.DNSNames) == 0 {
			return "", fmt.Errorf("name is empty and %s has no DNS name in its subjectAltName; set ddr.name", path)
		}
		return cert.DNSNames[0], nil
	}
}

// DDRHints parses ddr.ipv4hint and ddr.ipv6hint, the addresses DDR carries as
// hints. The middleware and the config gate both call it. It refuses a value
// no client could connect to: not an address of the list's family, or not a
// global unicast one, which leaves out loopback, unspecified, multicast,
// link-local and the IPv4 limited broadcast. A private address is global
// unicast and fine, a resolver on a home or office network is reached at one.
func (c *Config) DDRHints() (v4, v6 []net.IP, err error) {
	for _, list := range []struct {
		key, family string
		values      []string
		is4         bool
	}{
		{"ipv4hint", "IPv4", c.DDR.IPv4Hint, true},
		{"ipv6hint", "IPv6", c.DDR.IPv6Hint, false},
	} {
		seen := make(map[netip.Addr]bool, len(list.values))
		for _, s := range list.values {
			addr, perr := netip.ParseAddr(s)
			switch {
			case perr != nil || addr.Zone() != "" || addr.Is4() != list.is4 || addr.Is4In6():
				return nil, nil, fmt.Errorf("ddr.%s: %q is not an %s address", list.key, s, list.family)
			case !addr.IsGlobalUnicast():
				return nil, nil, fmt.Errorf("ddr.%s: %q is not an address a client can connect to", list.key, s)
			case seen[addr]:
				return nil, nil, fmt.Errorf("ddr.%s: %q is listed twice", list.key, s)
			}
			seen[addr] = true
			if list.is4 {
				v4 = append(v4, net.IP(addr.AsSlice()))
			} else {
				v6 = append(v6, net.IP(addr.AsSlice()))
			}
		}
	}
	return v4, v6, nil
}
