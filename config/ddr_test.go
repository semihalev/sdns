package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert writes a self-signed certificate with the given subjectAltName
// entries and returns the certificate and key paths.
func writeCert(t *testing.T, dnsNames []string, ips []net.IP) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sdns test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestDDRTarget pins where the advertised name comes from and what it may
// not be: ddr.name wins, normalised; otherwise the certificate's first DNS
// name; a certificate with only IP addresses cannot supply one; and "." or a
// name under resolver.arpa is refused (RFC 9462 §4).
func TestDDRTarget(t *testing.T) {
	withNames, _ := writeCert(t, []string{"dns.example.net", "alt.example.net"}, []net.IP{net.ParseIP("192.0.2.53")})
	ipOnly, _ := writeCert(t, nil, []net.IP{net.ParseIP("192.0.2.53")})

	for _, tc := range []struct {
		name, ddrName, cert, want, errPart string
	}{
		{"explicit name, normalised", "DNS.Example.COM", withNames, "dns.example.com.", ""},
		{"explicit name wins over the certificate", "other.example.", withNames, "other.example.", ""},
		{"first DNS name of the certificate", "", withNames, "dns.example.net.", ""},
		{"certificate with IP addresses only", "", ipOnly, "", "no DNS name"},
		{"no name and no certificate", "", "", "", "no tlscertificate"},
		{"the root", ".", withNames, "", "not a domain name"},
		{"the zone itself", "resolver.arpa", withNames, "", "under resolver.arpa"},
		{"a name in the zone", "_dns.resolver.arpa.", withNames, "", "under resolver.arpa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{TLSCertificate: tc.cert}
			c.DDR.Name = tc.ddrName
			got, err := c.DDRTarget()
			if tc.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("got %q, %v; want an error mentioning %q", got, err, tc.errPart)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestValidateDDR: an enabled [ddr] with nothing to advertise, no encrypted
// listener or no usable name, fails the config gate; a disabled one is never
// judged, so a stale name under it keeps loading.
func TestValidateDDR(t *testing.T) {
	ipOnly, key := writeCert(t, nil, []net.IP{net.ParseIP("192.0.2.53")})
	named, namedKey := writeCert(t, []string{"dns.example.net"}, nil)

	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		errPart string
	}{
		{"enabled without an encrypted listener", func(c *Config) { c.DDR.Enabled = true; c.DDR.Name = "dns.example." }, "no encrypted listener"},
		{"enabled, certificate without a DNS name", func(c *Config) {
			c.DDR.Enabled = true
			c.BindTLS, c.TLSCertificate, c.TLSPrivateKey = ":853", ipOnly, key
		}, "ddr.name"},
		{"enabled and complete", func(c *Config) {
			c.DDR.Enabled = true
			c.BindDOH, c.TLSCertificate, c.TLSPrivateKey = ":443", named, namedKey
		}, ""},
		{"disabled with a name that could never work", func(c *Config) { c.DDR.Name = "resolver.arpa" }, ""},
		{"proxied DoH", func(c *Config) {
			c.DDR.Enabled, c.DDR.Name, c.DDR.DoHPort, c.DDR.DoHALPN = true, "dns.example.", 443, []string{"h2", "h3"}
			c.BindDOH = "127.0.0.1:8053"
		}, ""},
		{"doh_port out of range", func(c *Config) {
			c.DDR.Enabled, c.DDR.Name, c.DDR.DoHPort, c.BindDOH = true, "dns.example.", 70000, "127.0.0.1:8053"
		}, "ddr.doh_port"},
		{"doh_alpn that is not a DoH ALPN", func(c *Config) {
			c.DDR.Enabled, c.DDR.Name, c.DDR.DoHALPN, c.BindDOH = true, "dns.example.", []string{"http/1.1"}, ":443"
		}, "not a DoH ALPN"},
		{"doh_alpn listed twice", func(c *Config) {
			c.DDR.Enabled, c.DDR.Name, c.DDR.DoHALPN, c.BindDOH = true, "dns.example.", []string{"h2", "h2"}, ":443"
		}, "listed twice"},
		{"doh_port without a DoH listener", func(c *Config) {
			c.DDR.Enabled, c.DDR.Name, c.DDR.DoHPort, c.BindTLS = true, "dns.example.", 443, ":853"
		}, "no DoH listener to publish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := new(Config)
			tc.mutate(c)
			err := c.Validate()
			switch {
			case tc.errPart == "" && err != nil && strings.Contains(err.Error(), "ddr"):
				t.Fatalf("unexpected ddr problem: %v", err)
			case tc.errPart != "" && (err == nil || !strings.Contains(err.Error(), tc.errPart)):
				t.Fatalf("got %v, want a problem mentioning %q", err, tc.errPart)
			}
		})
	}
}
