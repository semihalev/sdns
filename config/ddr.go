package config

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
