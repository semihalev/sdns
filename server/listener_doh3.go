package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/semihalev/zlog/v2"
)

// doh3Listener serves DNS-over-HTTPS over HTTP/3 (RFC 9250 §4).
// Non-critical: HTTP/3 is optional transport.
type doh3Listener struct {
	addr    string
	handler http.Handler
	certs   certProvider

	mu      sync.Mutex
	srv     *http3.Server
	pc      net.PacketConn
	serving atomic.Bool
}

func newDOH3Listener(addr string, h http.Handler, certs certProvider) *doh3Listener {
	return &doh3Listener{addr: addr, handler: h, certs: certs}
}

func (d *doh3Listener) Proto() string  { return "doh3" }
func (d *doh3Listener) Addr() string   { return d.addr }
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

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", d.addr)
	if err != nil {
		return err
	}
	d.pc = pc
	d.srv = &http3.Server{
		Handler:   d.handler,
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			Allow0RTT: true,
			// Cap per-connection streams so a single client can't
			// monopolise the server by opening every stream the
			// default (100) allows and parking them. DoH3 is a
			// request/response protocol — 32 concurrent queries per
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
	srv, pc := d.srv, d.pc
	d.mu.Unlock()
	if srv == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "doh-h3", "addr", d.addr)
	d.serving.Store(true)
	defer d.serving.Store(false)
	err := srv.Serve(pc)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, quic.ErrServerClosed) {
		return err
	}
	return nil
}

func (d *doh3Listener) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	srv := d.srv
	pc := d.pc
	d.mu.Unlock()
	if srv == nil {
		return nil
	}

	zlog.Info("DNS server stopping", "net", "doh-h3", "addr", d.addr)
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
	if pc != nil {
		if cerr := pc.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
			err = cerr
		}
	}
	return err
}
