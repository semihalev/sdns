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

	"github.com/semihalev/zlog/v2"
)

// certProvider hands the listener a TLS config whose GetCertificate
// callback follows rotation. Implemented by *Server and *CertManager.
type certProvider interface {
	GetTLSConfig() *tls.Config
}

// tlsListener is the TCP engine behind a tls.Listener: DoT is the same
// inline per-connection loop, the handshake covered by the first-frame
// read deadline on the tls.Conn. Several addresses are one accept loop
// each over the one engine, as for plain TCP.
type tlsListener struct {
	addrs    []string
	handler  rawHandler
	certs    certProvider
	maxConns int
	plan     resourcePlan
	timeout  time.Duration

	mu       sync.Mutex
	lns      []net.Listener
	engine   *tcpEngine
	done     chan struct{}
	shutdown sync.Once
	closing  atomic.Bool
	drainErr error
	serving  atomic.Bool
}

func newTLSListener(addrs []string, h rawHandler, certs certProvider, timeout time.Duration, maxConns int, plan resourcePlan) *tlsListener {
	return &tlsListener{addrs: addrs, handler: h, certs: certs, timeout: timeout, maxConns: maxConns, plan: plan}
}

func (l *tlsListener) Proto() string  { return "tls" }
func (l *tlsListener) Addr() string   { return strings.Join(l.addrs, ", ") }
func (l *tlsListener) Critical() bool { return false }
func (l *tlsListener) Serving() bool  { return l.serving.Load() }

func (l *tlsListener) Bind(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lns != nil {
		return errors.New("tls listener: Bind called twice")
	}
	if l.certs == nil {
		return errors.New("no TLS certificate configured")
	}
	tlsConfig := l.certs.GetTLSConfig()
	if tlsConfig == nil {
		return errors.New("TLS certificate not available")
	}
	tlsConfig = withDoTALPN(tlsConfig)
	lns, err := listenTCPAll(ctx, l.addrs, func(ln net.Listener) net.Listener {
		return tls.NewListener(ln, tlsConfig)
	})
	if err != nil {
		return err
	}
	l.lns = lns
	l.engine = newTCPEngine(l.handler, "tls", l.maxConns, l.plan)
	l.done = make(chan struct{})
	return nil
}

func (l *tlsListener) Serve(_ context.Context) error {
	l.mu.Lock()
	lns, engine, done := l.lns, l.engine, l.done
	l.mu.Unlock()
	if lns == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "tcp-tls", "addr", l.Addr(),
		"maxconns", engine.maxConns, "smalljobs", cap(engine.smallTokens), "largejobs", cap(engine.largeTokens))
	l.serving.Store(true)
	defer l.serving.Store(false)

	for _, ln := range lns {
		addr := ln.Addr().String()
		if !engine.startAccepting(ln, func() {
			if !l.closing.Load() {
				zlog.Error("DoT accept loop exited outside shutdown", "addr", addr)
				recordListenerErr("tls")
			}
		}) {
			// Shutdown got here first and the engine refused the loop
			// rather than joining a barrier that is already being waited
			// on; it closed this socket, and Shutdown closes the rest.
			break
		}
	}

	<-done
	return l.drainErr
}

func (l *tlsListener) Shutdown(_ context.Context) error {
	l.mu.Lock()
	lns, engine := l.lns, l.engine
	l.mu.Unlock()
	if lns == nil {
		return nil
	}

	l.shutdown.Do(func() {
		timeout := l.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		zlog.Info("DNS server stopping", "net", "tcp-tls", "addr", l.Addr())

		l.closing.Store(true)
		for _, ln := range lns {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				l.drainErr = errors.Join(l.drainErr, err)
			}
		}
		if err := engine.shutdown(time.Now().Add(timeout)); err != nil {
			l.drainErr = errors.Join(l.drainErr, err)
		}
		close(l.done)
	})
	return l.drainErr
}

// Quiesced reports whether the engine holds no in-flight work.
func (l *tlsListener) Quiesced() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.engine == nil || l.engine.quiesced()
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

// dotALPN is the ALPN identifier for DNS over TLS (RFC 9461 §4.1), the one a
// client that found this listener through DDR connects with.
const dotALPN = "dot"

// withDoTALPN selects "dot" for a client that offers it and leaves every
// other handshake as it was. Setting NextProtos on the config itself would
// make the TLS stack refuse a client whose ALPN list does not contain "dot",
// and DoT clients that predate RFC 9461 offer other lists or none; those
// must keep connecting exactly as before.
func withDoTALPN(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, p := range hello.SupportedProtos {
			if p == dotALPN {
				selected := base.Clone()
				selected.NextProtos = []string{dotALPN}
				return selected, nil
			}
		}
		return nil, nil
	}
	return cfg
}
