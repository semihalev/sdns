package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/semihalev/sdns/config"
)

// twoAddrs is two loopback addresses a listener can hold at once.
var twoAddrs = []string{"127.0.0.1:0", "127.0.0.1:0"}

// serveListener binds and serves l, and returns the distinct addresses it
// holds once it reports serving.
func serveListener(t *testing.T, l Listener) []string {
	t.Helper()
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- l.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = l.Shutdown(context.Background())
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve did not return after shutdown")
		}
	})
	for deadline := time.Now().Add(3 * time.Second); !l.Serving(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s listener did not come up", l.Proto())
		}
		time.Sleep(time.Millisecond)
	}
	return boundAddrs(t, l)
}

// TestListenersServeEveryAddress: a listener given two addresses answers on
// both, whatever the transport. One engine behind several sockets is the
// point of the design, so every accept or read loop has to be running.
func TestListenersServeEveryAddress(t *testing.T) {
	certs := &fakeCerts{cfg: minimalTLSConfig(t)}
	httpOK := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	dnsExchange := func(net string) func(t *testing.T, addr string) {
		return func(t *testing.T, addr string) {
			c := &dns.Client{Net: net, Timeout: 3 * time.Second,
				TLSConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // loopback test server
			q := new(dns.Msg)
			q.SetQuestion("multi.example.", dns.TypeA)
			r, _, err := c.Exchange(q, addr)
			if err != nil || len(r.Answer) != 1 {
				t.Fatalf("%s %s: %v, %v", net, addr, r, err)
			}
		}
	}
	httpGet := func(rt http.RoundTripper) func(t *testing.T, addr string) {
		return func(t *testing.T, addr string) {
			c := &http.Client{Transport: rt, Timeout: 3 * time.Second}
			resp, err := c.Get("https://" + addr + "/")
			if err != nil {
				t.Fatalf("%s: %v", addr, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d", addr, resp.StatusCode)
			}
		}
	}
	insecure := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // loopback test server

	for _, tc := range []struct {
		name  string
		build func() Listener
		query func(t *testing.T, addr string)
	}{
		{"udp", func() Listener {
			return newUDPListener(twoAddrs, answer, time.Second, 0, 0, defaultResourcePlan(1))
		}, dnsExchange("udp")},
		{"tcp", func() Listener {
			return newTCPListener(twoAddrs, answer, time.Second, 8, defaultResourcePlan(1))
		}, dnsExchange("tcp")},
		{"tls", func() Listener {
			return newTLSListener(twoAddrs, answer, certs, time.Second, 8, defaultResourcePlan(1))
		}, dnsExchange("tcp-tls")},
		{"doq", func() Listener {
			return newDOQListener(twoAddrs, answer, certs, time.Second, defaultResourcePlanWith(1, true))
		}, func(t *testing.T, addr string) {
			conn, err := dialDoQ(t, addr)
			if err != nil {
				t.Fatalf("%s: %v", addr, err)
			}
			if r, err := exchange(conn, framedQuery(t, 0, nil), false); err != nil || len(r.Answer) != 1 {
				t.Fatalf("doq %s: %v, %v", addr, r, err)
			}
		}},
		{"doh", func() Listener {
			return newDOHListener(twoAddrs, httpOK, certs, time.Second)
		}, httpGet(&http.Transport{TLSClientConfig: insecure})},
		{"doh3", func() Listener {
			return newDOH3Listener(twoAddrs, httpOK, certs)
		}, httpGet(&http3.Transport{TLSClientConfig: insecure})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addrs := serveListener(t, tc.build())
			if len(addrs) != len(twoAddrs) {
				t.Fatalf("holds %v, want one socket group per address", addrs)
			}
			for _, addr := range addrs {
				tc.query(t, addr)
			}
		})
	}
}

// TestListenersBindEveryAddressOrNone: when one address cannot be opened the
// listener fails, naming it, and leaves none of the others open.
func TestListenersBindEveryAddressOrNone(t *testing.T) {
	certs := &fakeCerts{cfg: minimalTLSConfig(t)}
	handler := answer
	httpOK := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	for _, tc := range []struct {
		name  string
		udp   bool
		build func(addrs []string) Listener
	}{
		{"udp", true, func(addrs []string) Listener {
			return newUDPListener(addrs, handler, time.Second, 0, 0, defaultResourcePlan(1))
		}},
		{"tcp", false, func(addrs []string) Listener {
			return newTCPListener(addrs, handler, time.Second, 8, defaultResourcePlan(1))
		}},
		{"tls", false, func(addrs []string) Listener {
			return newTLSListener(addrs, handler, certs, time.Second, 8, defaultResourcePlan(1))
		}},
		{"doh", false, func(addrs []string) Listener { return newDOHListener(addrs, httpOK, certs, time.Second) }},
		{"doh3", true, func(addrs []string) Listener { return newDOH3Listener(addrs, httpOK, certs) }},
		{"doq", true, func(addrs []string) Listener {
			return newDOQListener(addrs, handler, certs, time.Second, defaultResourcePlanWith(1, true))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// free is a port nothing holds; taken is one something does.
			var free, taken string
			if tc.udp {
				hold, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer hold.Close()
				taken = hold.LocalAddr().String()
				probe, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				free = probe.LocalAddr().String()
				_ = probe.Close()
			} else {
				hold, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer hold.Close()
				taken = hold.Addr().String()
				probe, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				free = probe.Addr().String()
				_ = probe.Close()
			}

			l := tc.build([]string{free, taken})
			err := l.Bind(context.Background())
			if err == nil || !strings.Contains(err.Error(), taken) {
				_ = l.Shutdown(context.Background())
				t.Fatalf("Bind() = %v, want a failure naming %s", err, taken)
			}
			if tc.udp {
				probeUDP(t, free)
			} else {
				probeTCP(t, free)
			}
		})
	}
}

// TestUDPListenerRefusesMixedWildcard: the pktinfo decision is the engine's,
// so a wildcard and a specific address cannot share one listener even when
// the config gate was skipped.
func TestUDPListenerRefusesMixedWildcard(t *testing.T) {
	l := newUDPListener([]string{"127.0.0.1:0", ":0"}, answer, time.Second, 0, 0, defaultResourcePlan(1))
	if err := l.Bind(context.Background()); err == nil || !strings.Contains(err.Error(), "wildcard") {
		_ = l.Shutdown(context.Background())
		t.Fatalf("Bind() = %v, want the mix refused", err)
	}
}

// TestAltSvcPort: HTTP/3 is advertised on the port the request arrived on,
// which with several DoH addresses the configured list alone cannot say.
func TestAltSvcPort(t *testing.T) {
	s := &Server{cfg: &config.Config{BindDOH: config.Addrs{"192.0.2.53:443", "192.0.2.54:8443"}}}
	r, _ := http.NewRequest(http.MethodGet, "https://dns.example/dns-query", nil)
	if got := s.altSvcPort(r); got != "443" {
		t.Fatalf("without a connection: %q, want the first configured port 443", got)
	}
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.54"), Port: 8443}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(local)))
	if got := s.altSvcPort(r); got != "8443" {
		t.Fatalf("on 192.0.2.54:8443: %q, want 8443", got)
	}
}
