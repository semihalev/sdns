package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/semihalev/sdns/server/doq"
	"github.com/semihalev/zlog/v2"
)

// doqListener serves DNS-over-QUIC (RFC 9250). Non-critical.
type doqListener struct {
	addr    string
	handler dns.Handler
	certs   certProvider

	mu      sync.Mutex
	srv     *doq.Server
	pc      net.PacketConn
	serving atomic.Bool
}

func newDOQListener(addr string, h dns.Handler, certs certProvider) *doqListener {
	return &doqListener{addr: addr, handler: h, certs: certs}
}

func (d *doqListener) Proto() string  { return "doq" }
func (d *doqListener) Addr() string   { return d.addr }
func (d *doqListener) Critical() bool { return false }
func (d *doqListener) Serving() bool  { return d.serving.Load() }

func (d *doqListener) Bind(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.srv != nil {
		return errors.New("doq listener: Bind called twice")
	}
	if d.certs == nil {
		return errors.New("no TLS certificate configured")
	}
	if d.certs.GetTLSConfig() == nil {
		return errors.New("TLS certificate not available")
	}

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", d.addr)
	if err != nil {
		return err
	}
	d.pc = pc
	d.srv = &doq.Server{Addr: d.addr, Handler: d.handler}
	return nil
}

func (d *doqListener) Serve(_ context.Context) error {
	d.mu.Lock()
	srv, pc, certs := d.srv, d.pc, d.certs
	d.mu.Unlock()
	if srv == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "doq", "addr", d.addr)
	d.serving.Store(true)
	defer d.serving.Store(false)
	err := srv.Serve(pc, certs.GetTLSConfig())
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, quic.ErrServerClosed) {
		return err
	}
	return nil
}

func (d *doqListener) Shutdown(_ context.Context) error {
	d.mu.Lock()
	srv := d.srv
	pc := d.pc
	d.mu.Unlock()
	if srv == nil {
		return nil
	}

	zlog.Info("DNS server stopping", "net", "doq", "addr", d.addr)
	// quic.Listener.Close (invoked by doq.Server.Shutdown) stops
	// accepting new QUIC connections but does not close the
	// caller-owned PacketConn. Close the socket ourselves so the
	// UDP port is released for restart.
	err := srv.Shutdown()
	if pc != nil {
		if cerr := pc.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
			err = cerr
		}
	}
	return err
}
