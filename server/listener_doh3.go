package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/semihalev/zlog/v2"
)

// doh3Listener serves DNS-over-HTTPS over HTTP/3 (RFC 9250 §4).
// Non-critical: HTTP/3 is optional transport. Several addresses are one
// HTTP/3 server serving each of their sockets.
type doh3Listener struct {
	addrs   []string
	handler http.Handler
	certs   certProvider

	mu      sync.Mutex
	srv     *http3.Server
	pcs     []net.PacketConn
	serving atomic.Bool
}

func newDOH3Listener(addrs []string, h http.Handler, certs certProvider) *doh3Listener {
	return &doh3Listener{addrs: addrs, handler: h, certs: certs}
}

func (d *doh3Listener) Proto() string  { return "doh3" }
func (d *doh3Listener) Addr() string   { return strings.Join(d.addrs, ", ") }
func (d *doh3Listener) Critical() bool { return false }
func (d *doh3Listener) Serving() bool  { return d.serving.Load() }

func (d *doh3Listener) Bind(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.srv != nil {
		return errors.New("doh3 listener: Bind called twice")
	}
	if d.certs == nil {
		return errors.New("no TLS certificate configured")
	}
	tlsConfig := d.certs.GetTLSConfig()
	if tlsConfig == nil {
		return errors.New("TLS certificate not available")
	}

	pcs, err := listenUDPAll(ctx, d.addrs)
	if err != nil {
		return err
	}
	d.pcs = pcs
	d.srv = &http3.Server{
		Handler:   d.handler,
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			Allow0RTT: true,
			// Cap per-connection streams so a single client can't
			// monopolise the server by opening every stream the
			// default (100) allows and parking them. DoH3 is a
			// request/response protocol, 32 concurrent queries per
			// connection is plenty for any real client and leaves
			// ample headroom for normal pipelining.
			MaxIncomingStreams:    32,
			MaxIncomingUniStreams: 8,
			// 5m idle covers keep-alive patterns for real DoH3
			// clients (Firefox, Chrome) without letting dead
			// connections squat indefinitely.
			MaxIdleTimeout: 5 * time.Minute,
		},
	}
	return nil
}

func (d *doh3Listener) Serve(_ context.Context) error {
	d.mu.Lock()
	srv, pcs := d.srv, d.pcs
	d.mu.Unlock()
	if srv == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "doh-h3", "addr", d.Addr())
	d.serving.Store(true)
	defer d.serving.Store(false)
	errs := make(chan error, len(pcs))
	for _, pc := range pcs {
		go func() { errs <- srv.Serve(pc) }()
	}
	var serveErr error
	for range pcs {
		err := <-errs
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, quic.ErrServerClosed) {
			serveErr = errors.Join(serveErr, err)
		}
	}
	return serveErr
}

func (d *doh3Listener) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	srv := d.srv
	pcs := d.pcs
	d.mu.Unlock()
	if srv == nil {
		return nil
	}

	zlog.Info("DNS server stopping", "net", "doh-h3", "addr", d.Addr())
	// Shutdown sends a GOAWAY and waits for in-flight requests to
	// complete within ctx, rather than aborting them mid-stream the
	// way Close would. If ctx fires before drain completes, Shutdown
	// returns its error and we fall through to Close to kill the
	// remaining handlers so the port still releases promptly.
	err := srv.Shutdown(ctx)
	if err != nil {
		_ = srv.Close()
	}
	// http3.Server.Shutdown / Close stop accepting new streams but do
	// not close the caller-provided PacketConn (verified against
	// quic-go v0.59 http3/server.go and server.go). Close the socket
	// ourselves so the UDP port is actually released and graceful
	// restart / repeated start-stop cycles don't leak the bind.
	for _, pc := range pcs {
		if cerr := pc.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
			err = cerr
		}
	}
	return err
}
