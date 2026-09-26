package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/semihalev/zlog/v2"
)

// doqListener serves DNS-over-QUIC (RFC 9250) on the DoQ engine.
// Non-critical.
type doqListener struct {
	addr    string
	handler rawHandler
	certs   certProvider
	timeout time.Duration
	plan    resourcePlan

	mu       sync.Mutex
	pc       net.PacketConn
	tls      *tls.Config
	ln       *quic.Listener
	engine   *doqEngine
	shutdown sync.Once
	drainErr error
	serving  atomic.Bool
}

func newDOQListener(addr string, h rawHandler, certs certProvider, timeout time.Duration, plan resourcePlan) *doqListener {
	return &doqListener{addr: addr, handler: h, certs: certs, timeout: timeout, plan: plan}
}

func (d *doqListener) Proto() string  { return "doq" }
func (d *doqListener) Addr() string   { return d.addr }
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

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", d.addr)
	if err != nil {
		return err
	}
	d.pc = pc
	d.engine = newDoQEngine(d.handler, d.plan)
	return nil
}

func (d *doqListener) Serve(_ context.Context) error {
	d.mu.Lock()
	engine, pc, tlsConfig := d.engine, d.pc, d.tls
	d.mu.Unlock()
	if engine == nil {
		return errListenerNotBound
	}

	ln, err := quic.Listen(pc, tlsConfig, doqQUICConfig())
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.ln = ln
	d.mu.Unlock()

	zlog.Info("DNS server listening", "net", "doq", "addr", d.addr,
		"maxconns", engine.maxConns, "jobs", cap(engine.tokens))
	d.serving.Store(true)
	defer d.serving.Store(false)
	// The accept loop returns only by failing, and shutting down is one of
	// those failures, arriving as one of the two errors swallowed here.
	err = engine.serve(ln)
	if !errors.Is(err, net.ErrClosed) && !errors.Is(err, quic.ErrServerClosed) {
		return err
	}
	return nil
}

func (d *doqListener) Shutdown(_ context.Context) error {
	d.mu.Lock()
	engine, ln, pc := d.engine, d.ln, d.pc
	d.mu.Unlock()
	if engine == nil {
		return nil
	}

	d.shutdown.Do(func() {
		timeout := d.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		zlog.Info("DNS server stopping", "net", "doq", "addr", d.addr)
		if ln != nil {
			if err := ln.Close(); err != nil && !errors.Is(err, quic.ErrServerClosed) {
				d.drainErr = errors.Join(d.drainErr, err)
			}
		}
		if err := engine.shutdown(time.Now().Add(timeout)); err != nil {
			d.drainErr = errors.Join(d.drainErr, err)
		}
		// The listener does not own the socket it was handed; closing it
		// here is what releases the port for a restart.
		if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			d.drainErr = errors.Join(d.drainErr, err)
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
