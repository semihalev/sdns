package forwarder

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// startNamedDoTServer runs a DoT server on a loopback address whose
// certificate names only dns.test, with no IP address in it: the shape of
// a provider whose certificate carries its service name, not its address.
// It returns the address, a pool trusting the certificate, and the SNI the
// last handshake sent.
func startNamedDoTServer(t *testing.T) (addr string, roots *x509.CertPool, sni *atomic.Value) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "dns.test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"dns.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(leaf)

	sni = new(atomic.Value)
	sni.Store("")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni.Store(hello.ServerName)
			return nil, nil
		},
	})
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		a, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.7")
		m.Answer = []dns.RR{a}
		_ = w.WriteMsg(m)
	})
	s := &dns.Server{Net: "tcp-tls", Listener: tlsLn, Handler: mux}
	go func() { _ = s.ActivateAndServe() }()
	t.Cleanup(func() { _ = s.Shutdown() })
	return ln.Addr().String(), roots, sni
}

// forwardOnce builds a forwarder over upstreams, trusting roots for every
// DoT server, and reports the rcode one query came back with.
func forwardOnce(t *testing.T, roots *x509.CertPool, upstreams ...string) int {
	t.Helper()
	f := New(&config.Config{ForwarderServers: upstreams})
	f.tlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	for _, srv := range f.servers {
		if srv.TLSConfig != nil {
			srv.TLSConfig.RootCAs = roots
		}
	}
	req := new(dns.Msg)
	req.SetQuestion("named.example.", dns.TypeA)
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{f})
	ch.Reset(w, req)
	ch.Next(context.Background())
	return w.Rcode()
}

// A DoT upstream given as an address and a name connects to the address
// and holds the server to the name: the name goes out as SNI, a certificate
// valid for it is accepted though it names no IP, and one that is not is
// refused. The name is never resolved, dns.test has no address anywhere.
// Without a name the certificate must name the IP, as it always had to.
func TestDoTAuthenticatesTheConfiguredName(t *testing.T) {
	addr, roots, sni := startNamedDoTServer(t)

	if rcode := forwardOnce(t, roots, "tls://"+addr+"#dns.test"); rcode != dns.RcodeSuccess {
		t.Fatalf("with the certificate's name: rcode %s, want NOERROR", dns.RcodeToString[rcode])
	}
	if got := sni.Load().(string); got != "dns.test" {
		t.Fatalf("SNI %q, want dns.test", got)
	}

	if rcode := forwardOnce(t, roots, "tls://"+addr+"#other.test"); rcode != dns.RcodeServerFailure {
		t.Fatalf("with a name the certificate does not carry: rcode %s, want SERVFAIL", dns.RcodeToString[rcode])
	}
	if rcode := forwardOnce(t, roots, "tls://"+addr); rcode != dns.RcodeServerFailure {
		t.Fatalf("without a name, against a certificate naming no IP: rcode %s, want SERVFAIL", dns.RcodeToString[rcode])
	}
}

// Names differing only in case are one name, so their repeats are one
// upstream: they must not spend the attempts a query gets before a later,
// different name is ever tried.
func TestDoTNameRepeatsInAnotherCaseAreOneUpstream(t *testing.T) {
	addr, roots, _ := startNamedDoTServer(t)

	rcode := forwardOnce(t, roots,
		"tls://"+addr+"#wrong.test", "tls://"+addr+"#WRONG.test", "tls://"+addr+"#Wrong.Test.", "tls://"+addr+"#dns.test")
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode %s, want NOERROR from dns.test after one failed wrong.test", dns.RcodeToString[rcode])
	}
}

// A name is part of what a DoT upstream is: one address under two names is
// two servers, and a repeat of either is dropped.
func TestDoTUpstreamsAreKeyedByName(t *testing.T) {
	servers := parseServers([]string{
		"tls://192.0.2.1:853",
		"tls://192.0.2.1:853#a.example",
		"tls://192.0.2.1:853#b.example",
		"tls://192.0.2.1:853#a.example",
		"tls://192.0.2.1:853#A.Example.",
		"tls://192.0.2.1:853",
		"tls://192.0.2.1:853#bad_name",
	}, time.Second, time.Second, "test")
	var got []string
	for _, s := range servers {
		got = append(got, s.Addr+"#"+s.AuthName)
		if s.Addr != "192.0.2.1:853" {
			t.Fatalf("address %q kept the name", s.Addr)
		}
		if (s.AuthName != "") != (s.TLSConfig != nil) || s.TLSConfig != nil && s.TLSConfig.ServerName != s.AuthName {
			t.Fatalf("server %q: TLS config does not carry its name", s.AuthName)
		}
	}
	want := []string{"192.0.2.1:853#", "192.0.2.1:853#a.example", "192.0.2.1:853#b.example"}
	if len(got) != len(want) {
		t.Fatalf("servers %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("servers %v, want %v", got, want)
		}
	}
}
