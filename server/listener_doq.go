package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/semihalev/zlog/v2"
)

// doqListener serves DNS-over-QUIC (RFC 9250) on the DoQ engine.
// Non-critical. Several addresses are one QUIC listener each over the one
// engine, so the connection and stream bounds are the transport's.
type doqListener struct {
	addrs   []string
	handler rawHandler
	certs   certProvider
	timeout time.Duration
	plan    resourcePlan

	mu       sync.Mutex
	pcs      []net.PacketConn
	tls      *tls.Config
	lns      []*quic.Listener
	engine   *doqEngine
	shutdown sync.Once
	closed   bool // Shutdown has run; a late Serve opens no listener
	drainErr error
	serving  atomic.Bool
}

func newDOQListener(addrs []string, h rawHandler, certs certProvider, timeout time.Duration, plan resourcePlan) *doqListener {
	return &doqListener{addrs: addrs, handler: h, certs: certs, timeout: timeout, plan: plan}
}

func (d *doqListener) Proto() string  { return "doq" }
func (d *doqListener) Addr() string   { return strings.Join(d.addrs, ", ") }
func (d *doqListener) Critical() bool { return false }
func (d *doqListener) Serving() bool  { return d.serving.Load() }

func (d *doqListener) Bind(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.engine != nil {
		return errors.New("doq listener: Bind called twice")
	}
	if d.certs == nil {
		return errors.New("no TLS certificate configured")
	}
	// Taken once, here, and used by Serve. Fetching again at serve time
	// raced shutdown: a late Serve after the supervisor had stopped the
	// certificate manager would make the provider build a fresh one,
	// leaving a watcher alive behind a Stopped() that already said true.
	// The config carries a GetCertificate callback, so reloads still
	// flow through it.
	tlsConfig := d.certs.GetTLSConfig()
	if tlsConfig == nil {
		return errors.New("TLS certificate not available")
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{doqALPN}
	tlsConfig.MinVersion = tls.VersionTLS13
	d.tls = tlsConfig

	pcs, err := listenUDPAll(ctx, d.addrs)
	if err != nil {
		return err
	}
	d.pcs = pcs
	d.engine = newDoQEngine(d.handler, d.plan)
	return nil
}

func (d *doqListener) Serve(_ context.Context) error {
	d.mu.Lock()
	engine, pcs, tlsConfig := d.engine, d.pcs, d.tls
	if engine == nil {
		d.mu.Unlock()
		return errListenerNotBound
	}
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	// The QUIC listeners are made under the lock Shutdown takes, so each is
	// either recorded for it to close or never made.
	var err error
	for _, pc := range pcs {
		var ln *quic.Listener
		if ln, err = quic.Listen(pc, tlsConfig, doqQUICConfig()); err != nil {
			break
		}
		d.lns = append(d.lns, ln)
	}
	lns := d.lns
	d.mu.Unlock()
	if err != nil {
		for _, ln := range lns {
			_ = ln.Close()
		}
		return err
	}

	zlog.Info("DNS server listening", "net", "doq", "addr", d.Addr(),
		"maxconns", engine.maxConns, "jobs", cap(engine.tokens))
	d.serving.Store(true)
	defer d.serving.Store(false)
	// Each accept loop returns only by failing, and shutting down is one of
	// those failures, arriving as one of the two errors swallowed here.
	errs := make(chan error, len(lns))
	for _, ln := range lns {
		go func() { errs <- engine.serve(ln) }()
	}
	var serveErr error
	for range lns {
		if err := <-errs; !errors.Is(err, net.ErrClosed) && !errors.Is(err, quic.ErrServerClosed) {
			serveErr = errors.Join(serveErr, err)
		}
	}
	return serveErr
}

func (d *doqListener) Shutdown(_ context.Context) error {
	d.mu.Lock()
	engine, lns, pcs := d.engine, d.lns, d.pcs
	d.closed = true
	d.mu.Unlock()
	if engine == nil {
		return nil
	}

	d.shutdown.Do(func() {
		timeout := d.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		zlog.Info("DNS server stopping", "net", "doq", "addr", d.Addr())
		for _, ln := range lns {
			if err := ln.Close(); err != nil && !errors.Is(err, quic.ErrServerClosed) {
				d.drainErr = errors.Join(d.drainErr, err)
			}
		}
		if err := engine.shutdown(time.Now().Add(timeout)); err != nil {
			d.drainErr = errors.Join(d.drainErr, err)
		}
		// The listener does not own the sockets it was handed; closing them
		// here is what releases the ports for a restart.
		for _, pc := range pcs {
			if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				d.drainErr = errors.Join(d.drainErr, err)
			}
		}
	})
	return d.drainErr
}

// Quiesced reports whether the engine holds no in-flight stream.
func (d *doqListener) Quiesced() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.engine == nil || d.engine.quiesced()
}

// TrimIdleMemory drops the engine's parked slabs (see trim.go).
func (d *doqListener) TrimIdleMemory() int {
	d.mu.Lock()
	engine := d.engine
	d.mu.Unlock()
	if engine == nil {
		return 0
	}
	return engine.trimIdle()
}
