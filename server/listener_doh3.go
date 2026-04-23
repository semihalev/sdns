package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

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

func (d *doh3Listener) Shutdown(_ context.Context) error {
	d.mu.Lock()
	srv := d.srv
	pc := d.pc
	d.mu.Unlock()
	if srv == nil {
		return nil
	}

	zlog.Info("DNS server stopping", "net", "doh-h3", "addr", d.addr)
	// http3.Server.Close stops accepting new streams but does not
	// close the caller-provided PacketConn (verified against
	// quic-go v0.59 http3/server.go and server.go). Close the
	// socket ourselves so the UDP port is actually released and
	// graceful restart / repeated start-stop cycles don't leak the
	// bind.
	err := srv.Close()
	if pc != nil {
		if cerr := pc.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
			err = cerr
		}
	}
	return err
}
