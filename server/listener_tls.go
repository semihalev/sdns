package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/semihalev/zlog/v2"
)

// certProvider hands the listener a TLS config whose GetCertificate
// callback follows rotation. Implemented by *Server and *CertManager.
type certProvider interface {
	GetTLSConfig() *tls.Config
}

// tlsListener is the TCP engine behind a tls.Listener: DoT is the same
// inline per-connection loop, the handshake covered by the first-frame
// read deadline on the tls.Conn.
type tlsListener struct {
	addr     string
	handler  rawHandler
	certs    certProvider
	maxConns int
	plan     resourcePlan
	timeout  time.Duration

	mu       sync.Mutex
	ln       net.Listener
	engine   *tcpEngine
	done     chan struct{}
	shutdown sync.Once
	closing  atomic.Bool
	drainErr error
	serving  atomic.Bool
}

func newTLSListener(addr string, h rawHandler, certs certProvider, timeout time.Duration, maxConns int, plan resourcePlan) *tlsListener {
	return &tlsListener{addr: addr, handler: h, certs: certs, timeout: timeout, maxConns: maxConns, plan: plan}
}

func (l *tlsListener) Proto() string  { return "tls" }
func (l *tlsListener) Addr() string   { return l.addr }
func (l *tlsListener) Critical() bool { return false }
func (l *tlsListener) Serving() bool  { return l.serving.Load() }

func (l *tlsListener) Bind(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		return errors.New("tls listener: Bind called twice")
	}
	if l.certs == nil {
		return errors.New("no TLS certificate configured")
	}
	tlsConfig := l.certs.GetTLSConfig()
	if tlsConfig == nil {
		return errors.New("TLS certificate not available")
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		return err
	}
	l.ln = tls.NewListener(ln, tlsConfig)
	l.engine = newTCPEngine(l.handler, "tls", l.maxConns, l.plan)
	l.done = make(chan struct{})
	return nil
}

func (l *tlsListener) Serve(_ context.Context) error {
	l.mu.Lock()
	ln, engine, done := l.ln, l.engine, l.done
	l.mu.Unlock()
	if ln == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "tcp-tls", "addr", l.addr,
		"maxconns", engine.maxConns, "smalljobs", cap(engine.smallTokens), "largejobs", cap(engine.largeTokens))
	l.serving.Store(true)
	defer l.serving.Store(false)

	if !engine.startAccepting(ln, func() {
		if !l.closing.Load() {
			zlog.Error("DoT accept loop exited outside shutdown", "addr", l.addr)
			recordListenerErr("tls")
		}
	}) {
		// Shutdown got here first and the engine refused the loop rather
		// than joining a barrier that is already being waited on. The
		// listener is closed; there is nothing to serve.
		<-done
		return l.drainErr
	}

	<-done
	return l.drainErr
}

func (l *tlsListener) Shutdown(_ context.Context) error {
	l.mu.Lock()
	ln, engine := l.ln, l.engine
	l.mu.Unlock()
	if ln == nil {
		return nil
	}

	l.shutdown.Do(func() {
		timeout := l.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		zlog.Info("DNS server stopping", "net", "tcp-tls", "addr", l.addr)

		l.closing.Store(true)
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			l.drainErr = errors.Join(l.drainErr, err)
		}
		if err := engine.shutdown(time.Now().Add(timeout)); err != nil {
			l.drainErr = errors.Join(l.drainErr, err)
		}
		close(l.done)
	})
	return l.drainErr
}

// TrimIdleMemory drops the engine's parked slabs (see trim.go).
func (l *tlsListener) TrimIdleMemory() int {
	l.mu.Lock()
	engine := l.engine
	l.mu.Unlock()
	if engine == nil {
		return 0
	}
	return engine.trimIdle()
}
