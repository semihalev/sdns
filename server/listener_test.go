package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/semihalev/sdns/middleware"
)

// fakeListener is a test Listener whose Bind / Shutdown outcome is
// configurable, used to verify bindAll's cleanup contract without
// touching real sockets.
type fakeListener struct {
	proto    string
	addr     string
	critical bool
	bindErr  error

	bound    atomic.Bool
	shutdown atomic.Bool
}

func (f *fakeListener) Proto() string  { return f.proto }
func (f *fakeListener) Addr() string   { return f.addr }
func (f *fakeListener) Critical() bool { return f.critical }
func (f *fakeListener) Serving() bool  { return f.bound.Load() && !f.shutdown.Load() }

func (f *fakeListener) Bind(context.Context) error {
	if f.bindErr != nil {
		return f.bindErr
	}
	f.bound.Store(true)
	return nil
}

func (f *fakeListener) Serve(context.Context) error { return nil }

func (f *fakeListener) Shutdown(context.Context) error {
	f.shutdown.Store(true)
	return nil
}

func TestBindAll_CriticalFailureUnwindsSuccessfulBinds(t *testing.T) {
	// The production scenario: UDP binds fine, TCP critical bind
	// fails with address-already-in-use. bindAll must Shutdown the
	// already-bound UDP listener so no socket leaks.
	udp := &fakeListener{proto: "udp", addr: ":53", critical: true}
	tcp := &fakeListener{proto: "tcp", addr: ":53", critical: true, bindErr: errors.New("bind: address already in use")}
	tls := &fakeListener{proto: "tls", addr: ":853"}

	active, err := bindAll(context.Background(), []Listener{udp, tcp, tls})

	if err == nil {
		t.Fatalf("%s: expected an error, got nil", "bindAll must surface critical bind errors")
	}
	if active != nil {
		t.Errorf("%s: active = %v, want nil", "no listeners should be returned on critical failure", active)
	}
	if !strings.Contains(err.Error(), "bind: address already in use") {
		t.Errorf("%q does not contain %q", err.Error(), "bind: address already in use")
	}

	if !(udp.bound.Load()) {
		t.Errorf("%s: udp.bound.Load() is false", "UDP should have bound")
	}
	if !(udp.shutdown.Load()) {
		t.Errorf("%s: udp.shutdown.Load() is false", "UDP must be shut down to release the socket")
	}
	if tcp.bound.Load() {
		t.Errorf("%s: tcp.bound.Load() is true", "TCP should not have bound")
	}
	if !(tls.bound.Load()) {
		t.Errorf("%s: tls.bound.Load() is false", "non-critical TLS should have bound")
	}
	if !(tls.shutdown.Load()) {
		t.Errorf("%s: tls.shutdown.Load() is false", "non-critical TLS must also be shut down")
	}
}

func TestBindAll_NonCriticalFailureDoesNotAbort(t *testing.T) {
	// TLS bind fails (missing cert) but UDP+TCP are fine, startup
	// should continue with a disabled TLS listener.
	udp := &fakeListener{proto: "udp", addr: ":53", critical: true}
	tcp := &fakeListener{proto: "tcp", addr: ":53", critical: true}
	tls := &fakeListener{proto: "tls", addr: ":853", bindErr: errors.New("no cert")}

	active, err := bindAll(context.Background(), []Listener{udp, tcp, tls})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(active) != 2 {
		t.Errorf("len(active) = %d, want %d", len(active), 2)
	}
	if !(udp.bound.Load()) {
		t.Errorf("udp.bound.Load() is false")
	}
	if !(tcp.bound.Load()) {
		t.Errorf("tcp.bound.Load() is false")
	}
	if tls.bound.Load() {
		t.Errorf("tls.bound.Load() is true")
	}
	// Nothing should be shut down, everything currently bound is
	// still serving.
	if udp.shutdown.Load() {
		t.Errorf("udp.shutdown.Load() is true")
	}
	if tcp.shutdown.Load() {
		t.Errorf("tcp.shutdown.Load() is true")
	}
}

// TestListenerShutdownBeforeServeReleasesSocket verifies that every
// socket-owning listener actually closes its underlying FD in
// Shutdown, even when Serve was never called, the bind-but-not-serve
// path that bindAll's partial-failure cleanup hits.
//
// miekg/dns's ShutdownContext and http.Server.Shutdown are both
// no-ops when the server hasn't started serving yet; this test pins
// the workaround (each listener now closes its own socket).
func TestListenerShutdownBeforeServeReleasesSocket(t *testing.T) {
	certs := &fakeCerts{cfg: minimalTLSConfig(t)}
	handler := rawHandlerFunc(func(middleware.Transport, []byte, time.Time) bool { return true })
	httpHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	cases := []struct {
		name  string
		build func(addrs []string) Listener
	}{
		{"udp", func(addrs []string) Listener {
			return newUDPListener(addrs, handler, time.Second, 0, 0, defaultResourcePlan(1))
		}},
		{"tcp", func(addrs []string) Listener {
			return newTCPListener(addrs, handler, time.Second, 0, defaultResourcePlan(1))
		}},
		{"tls", func(addrs []string) Listener {
			return newTLSListener(addrs, handler, certs, time.Second, 0, defaultResourcePlan(1))
		}},
		{"doh", func(addrs []string) Listener { return newDOHListener(addrs, httpHandler, certs, time.Second) }},
		{"doh3", func(addrs []string) Listener { return newDOH3Listener(addrs, httpHandler, certs) }},
		{"doq", func(addrs []string) Listener {
			return newDOQListener(addrs, handler, certs, time.Second, defaultResourcePlanWith(1, true))
		}},
	}

	for _, tc := range cases {
		for _, addrs := range [][]string{{"127.0.0.1:0"}, {"127.0.0.1:0", "127.0.0.1:0"}} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, len(addrs)), func(t *testing.T) {
				l := tc.build(addrs)
				if err := l.Bind(context.Background()); err != nil {
					t.Fatalf("%s: unexpected error: %v", "Bind", err)
				}

				// Capture the bound ports so we can try to re-bind them.
				bound := boundAddrs(t, l)
				if len(bound) != len(addrs) {
					t.Fatalf("bound %v, want one socket per address in %v", bound, addrs)
				}
				if err := l.Shutdown(context.Background()); err != nil {
					t.Fatalf("%s: unexpected error: %v", "Shutdown", err)
				}

				// If Shutdown actually released the FDs, we can open a
				// fresh socket on each port immediately. Use the
				// matching transport, UDP probe for UDP listeners, TCP
				// probe for the rest.
				for _, addr := range bound {
					if udpProto(tc.name) {
						probeUDP(t, addr)
					} else {
						probeTCP(t, addr)
					}
				}
			})
		}
	}
}

func udpProto(name string) bool {
	switch name {
	case "udp", "doh3", "doq":
		return true
	}
	return false
}

// boundAddrs reads the distinct bound addresses out of the concrete
// listener types. We need the resolved ports so we can probe the sockets
// after Shutdown. A UDP listener may hold several sockets on one port.
func boundAddrs(t *testing.T, l Listener) []string {
	t.Helper()
	var addrs []string
	add := func(a net.Addr) {
		if !slices.Contains(addrs, a.String()) {
			addrs = append(addrs, a.String())
		}
	}
	switch v := l.(type) {
	case *udpListener:
		for _, pc := range v.pcs {
			add(pc.LocalAddr())
		}
	case *tcpListener:
		for _, ln := range v.lns {
			add(ln.Addr())
		}
	case *tlsListener:
		for _, ln := range v.lns {
			add(ln.Addr())
		}
	case *dohListener:
		for _, ln := range v.lns {
			add(ln.Addr())
		}
	case *doh3Listener:
		for _, pc := range v.pcs {
			add(pc.LocalAddr())
		}
	case *doqListener:
		for _, pc := range v.pcs {
			add(pc.LocalAddr())
		}
	default:
		t.Fatalf("unsupported listener type %T", l)
	}
	return addrs
}

func probeUDP(t *testing.T, addr string) {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", fmt.Sprintf("port %s must be free after Shutdown", addr), err)
	}
	_ = pc.Close()
}

func probeTCP(t *testing.T, addr string) {
	t.Helper()
	ta, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ln, err := net.ListenTCP("tcp", ta)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", fmt.Sprintf("port %s must be free after Shutdown", addr), err)
	}
	_ = ln.Close()
}

// fakeCerts is a test-only certProvider backed by a static
// *tls.Config, used so the TLS-requiring listeners can Bind without
// a real CertManager.
type fakeCerts struct{ cfg *tls.Config }

func (f *fakeCerts) GetTLSConfig() *tls.Config { return f.cfg }

// minimalTLSConfig returns a tls.Config with one ephemeral
// self-signed cert, enough to satisfy Bind's nil-check without
// actually performing any handshake.
func minimalTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, key := generateTestCert(t, "listener-test.local")
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
}
