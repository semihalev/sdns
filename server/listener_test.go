package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	require.Error(t, err, "bindAll must surface critical bind errors")
	assert.Nil(t, active, "no listeners should be returned on critical failure")
	assert.Contains(t, err.Error(), "bind: address already in use")

	assert.True(t, udp.bound.Load(), "UDP should have bound")
	assert.True(t, udp.shutdown.Load(), "UDP must be shut down to release the socket")
	assert.False(t, tcp.bound.Load(), "TCP should not have bound")
	assert.True(t, tls.bound.Load(), "non-critical TLS should have bound")
	assert.True(t, tls.shutdown.Load(), "non-critical TLS must also be shut down")
}

func TestBindAll_NonCriticalFailureDoesNotAbort(t *testing.T) {
	// TLS bind fails (missing cert) but UDP+TCP are fine — startup
	// should continue with a disabled TLS listener.
	udp := &fakeListener{proto: "udp", addr: ":53", critical: true}
	tcp := &fakeListener{proto: "tcp", addr: ":53", critical: true}
	tls := &fakeListener{proto: "tls", addr: ":853", bindErr: errors.New("no cert")}

	active, err := bindAll(context.Background(), []Listener{udp, tcp, tls})

	require.NoError(t, err)
	assert.Len(t, active, 2)
	assert.True(t, udp.bound.Load())
	assert.True(t, tcp.bound.Load())
	assert.False(t, tls.bound.Load())
	// Nothing should be shut down — everything currently bound is
	// still serving.
	assert.False(t, udp.shutdown.Load())
	assert.False(t, tcp.shutdown.Load())
}

// TestListenerShutdownBeforeServeReleasesSocket verifies that every
// socket-owning listener actually closes its underlying FD in
// Shutdown, even when Serve was never called — the bind-but-not-serve
// path that bindAll's partial-failure cleanup hits.
//
// miekg/dns's ShutdownContext and http.Server.Shutdown are both
// no-ops when the server hasn't started serving yet; this test pins
// the workaround (each listener now closes its own socket).
func TestListenerShutdownBeforeServeReleasesSocket(t *testing.T) {
	certs := &fakeCerts{cfg: minimalTLSConfig(t)}
	handler := dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
	httpHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	cases := []struct {
		name  string
		build func(addr string) Listener
	}{
		{"udp", func(addr string) Listener { return newUDPListener(addr, handler, time.Second) }},
		{"tcp", func(addr string) Listener { return newTCPListener(addr, handler, time.Second) }},
		{"tls", func(addr string) Listener { return newTLSListener(addr, handler, certs, time.Second) }},
		{"doh", func(addr string) Listener { return newDOHListener(addr, httpHandler, certs, time.Second) }},
		{"doh3", func(addr string) Listener { return newDOH3Listener(addr, httpHandler, certs) }},
		{"doq", func(addr string) Listener { return newDOQListener(addr, handler, certs) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := tc.build("127.0.0.1:0")
			require.NoError(t, l.Bind(context.Background()), "Bind")

			// Capture the bound port so we can try to re-bind it.
			addr := boundAddr(t, l)
			require.NoError(t, l.Shutdown(context.Background()), "Shutdown")

			// If Shutdown actually released the FD, we can open a
			// fresh socket on the same port immediately. Use the
			// matching transport — UDP probe for UDP listeners, TCP
			// probe for the rest.
			if udpProto(tc.name) {
				probeUDP(t, addr)
			} else {
				probeTCP(t, addr)
			}
		})
	}
}

func udpProto(name string) bool {
	switch name {
	case "udp", "doh3", "doq":
		return true
	}
	return false
}

// boundAddr reads the bound address out of the concrete listener
// types. We need the resolved port so we can probe the socket
// after Shutdown.
func boundAddr(t *testing.T, l Listener) string {
	t.Helper()
	switch v := l.(type) {
	case *udpListener:
		require.NotEmpty(t, v.pcs, "udp listener must have at least one PacketConn")
		return v.pcs[0].LocalAddr().String()
	case *tcpListener:
		require.NotNil(t, v.ln, "tcp listener must have a net.Listener")
		return v.ln.Addr().String()
	case *tlsListener:
		require.NotNil(t, v.ln, "tls listener must have a net.Listener")
		return v.ln.Addr().String()
	case *dohListener:
		require.NotNil(t, v.ln, "doh listener must have a net.Listener")
		return v.ln.Addr().String()
	case *doh3Listener:
		require.NotNil(t, v.pc, "doh3 listener must have a PacketConn")
		return v.pc.LocalAddr().String()
	case *doqListener:
		require.NotNil(t, v.pc, "doq listener must have a PacketConn")
		return v.pc.LocalAddr().String()
	default:
		t.Fatalf("unsupported listener type %T", l)
		return ""
	}
}

func probeUDP(t *testing.T, addr string) {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err)
	pc, err := net.ListenUDP("udp", ua)
	require.NoError(t, err, "port %s must be free after Shutdown", addr)
	_ = pc.Close()
}

func probeTCP(t *testing.T, addr string) {
	t.Helper()
	ta, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)
	ln, err := net.ListenTCP("tcp", ta)
	require.NoError(t, err, "port %s must be free after Shutdown", addr)
	_ = ln.Close()
}

// fakeCerts is a test-only certProvider backed by a static
// *tls.Config, used so the TLS-requiring listeners can Bind without
// a real CertManager.
type fakeCerts struct{ cfg *tls.Config }

func (f *fakeCerts) GetTLSConfig() *tls.Config { return f.cfg }

// minimalTLSConfig returns a tls.Config with one ephemeral
// self-signed cert — enough to satisfy Bind's nil-check without
// actually performing any handshake.
func minimalTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, key := generateTestCert(t, "listener-test.local")
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
}
