package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// stateListener is a Listener whose bind outcome and serving state the test
// decides.
type stateListener struct {
	proto   string
	bindErr error
	serving atomic.Bool
}

func (f *stateListener) Proto() string                  { return f.proto }
func (f *stateListener) Addr() string                   { return "127.0.0.1:0" }
func (f *stateListener) Bind(context.Context) error     { return f.bindErr }
func (f *stateListener) Shutdown(context.Context) error { return nil }
func (f *stateListener) Critical() bool                 { return f.proto == "udp" }
func (f *stateListener) Serving() bool                  { return f.serving.Load() }
func (f *stateListener) Serve(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// observerHandler records the probe the server hands it.
type observerHandler struct {
	serving atomic.Pointer[func(string) bool]
}

func (o *observerHandler) Name() string { return "observer" }
func (o *observerHandler) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	ch.Next(ctx)
}
func (o *observerHandler) ObserveListeners(serving func(string) bool) {
	o.serving.Store(&serving)
}

// TestRunTellsObserversWhichListenersAreUp pins the wiring DDR depends on: a
// handler that describes the listeners is told, after the bind, which are
// actually up, so a listener whose bind failed is never reported, and one
// that bound but is not serving, a QUIC listener whose setup failed inside
// Serve, is reported down until it is.
func TestRunTellsObserversWhichListenersAreUp(t *testing.T) {
	obs := &observerHandler{}
	registry := middleware.NewRegistry()
	registry.Register("observer", func(*config.Config) middleware.Handler { return obs })
	s := &Server{cfg: &config.Config{}, pipeline: registry.Build(&config.Config{})}

	udp := &stateListener{proto: "udp"}
	dot := &stateListener{proto: "tls"}
	dot.serving.Store(true)
	doq := &stateListener{proto: "doq", bindErr: errors.New("address already in use")}
	doq.serving.Store(true) // would be up, but its bind failed
	doh3 := &stateListener{proto: "doh3"}
	s.listeners = []Listener{udp, dot, doq, doh3}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}

	p := obs.serving.Load()
	if p == nil {
		t.Fatal("the observer was never told about the listeners")
	}
	up := *p
	for proto, want := range map[string]bool{"tls": true, "doq": false, "doh3": false, "doh": false} {
		if got := up(proto); got != want {
			t.Errorf("serving(%q) = %v, want %v", proto, got, want)
		}
	}
	// Asked per call: the QUIC listener coming up later is seen.
	doh3.serving.Store(true)
	if !up("doh3") {
		t.Error("a listener that came up after Run was still reported down")
	}
}

// TestDoTSelectsDotALPNOnlyWhenOffered pins the DoT listener's ALPN: a
// client that offers "dot", the one DDR tells it to use, gets it selected;
// a client offering other protocols, or none, connects exactly as before
// with nothing selected rather than being refused.
func TestDoTSelectsDotALPNOnlyWhenOffered(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "dot.example")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	base := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	for _, tc := range []struct {
		name   string
		offers []string
		want   string
	}{
		{"offers dot", []string{"dot"}, "dot"},
		{"offers dot among others", []string{"h2", "dot"}, "dot"},
		{"offers something else", []string{"h2"}, ""},
		{"offers nothing", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			srv := tls.NewListener(ln, withDoTALPN(base))
			go func() {
				c, err := srv.Accept()
				if err == nil {
					_ = c.(*tls.Conn).Handshake()
					_ = c.Close()
				}
			}()
			d := &net.Dialer{Timeout: 2 * time.Second}
			c, err := tls.DialWithDialer(d, "tcp", ln.Addr().String(), &tls.Config{
				// The ALPN is under test here, not the certificate.
				InsecureSkipVerify: true, //nolint:gosec // G402 - test of ALPN selection only
				NextProtos:         tc.offers, MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				t.Fatalf("handshake refused: %v", err)
			}
			defer c.Close()
			if got := c.ConnectionState().NegotiatedProtocol; got != tc.want {
				t.Fatalf("negotiated %q, want %q", got, tc.want)
			}
		})
	}
}
