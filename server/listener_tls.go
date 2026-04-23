package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

// tlsListener serves DNS-over-TLS (RFC 7858). Non-critical: a missing
// certificate or a bad bind only disables DoT, never aborts startup.
type tlsListener struct {
	addr    string
	handler dns.Handler
	certs   certProvider
	timeout time.Duration

	mu      sync.Mutex
	srv     *dns.Server
	ln      net.Listener
	serving atomic.Bool
}

type certProvider interface {
	GetTLSConfig() *tls.Config
}

func newTLSListener(addr string, h dns.Handler, certs certProvider, timeout time.Duration) *tlsListener {
	return &tlsListener{addr: addr, handler: h, certs: certs, timeout: timeout}
}

func (l *tlsListener) Proto() string  { return "tls" }
func (l *tlsListener) Addr() string   { return l.addr }
func (l *tlsListener) Critical() bool { return false }
func (l *tlsListener) Serving() bool  { return l.serving.Load() }

func (l *tlsListener) Bind(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.srv != nil {
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
	l.srv = &dns.Server{
		Listener:      l.ln,
		Net:           "tcp-tls",
		Handler:       l.handler,
		MaxTCPQueries: 2048,
		TLSConfig:     tlsConfig,
	}
	return nil
}

func (l *tlsListener) Serve(_ context.Context) error {
	l.mu.Lock()
	srv := l.srv
	l.mu.Unlock()
	if srv == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "tls", "addr", l.addr)
	l.serving.Store(true)
	defer l.serving.Store(false)
	err := srv.ActivateAndServe()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (l *tlsListener) Shutdown(_ context.Context) error {
	l.mu.Lock()
	srv := l.srv
	ln := l.ln
	l.mu.Unlock()
	if srv == nil {
		return nil
	}

	timeout := l.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	zlog.Info("DNS server stopping", "net", "tls", "addr", l.addr)
	srvErr := srv.ShutdownContext(shutdownCtx)
	if ignoreShutdownErr(srvErr) {
		srvErr = nil
	}
	if ln != nil {
		// Closing the tls.Listener closes the underlying TCP
		// listener too, so this covers the bind-before-serve case.
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && srvErr == nil {
			srvErr = err
		}
	}
	return srvErr
}
