package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

// tcpListener serves plain DNS over a single TCP listener. TCP setup
// cost isn't a meaningful bottleneck for sdns so we don't fan it out
// the way we do UDP — one socket plus goroutine-per-connection is fine.
type tcpListener struct {
	addr    string
	handler dns.Handler
	timeout time.Duration

	mu      sync.Mutex
	srv     *dns.Server
	ln      net.Listener
	serving atomic.Bool
}

func newTCPListener(addr string, h dns.Handler, timeout time.Duration) *tcpListener {
	return &tcpListener{addr: addr, handler: h, timeout: timeout}
}

func (l *tcpListener) Proto() string  { return "tcp" }
func (l *tcpListener) Addr() string   { return l.addr }
func (l *tcpListener) Critical() bool { return true }
func (l *tcpListener) Serving() bool  { return l.serving.Load() }

func (l *tcpListener) Bind(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.srv != nil {
		return errors.New("tcp listener: Bind called twice")
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", l.addr)
	if err != nil {
		return err
	}
	l.ln = ln
	l.srv = &dns.Server{
		Listener:      ln,
		Net:           "tcp",
		Handler:       l.handler,
		MaxTCPQueries: 2048,
	}
	return nil
}

func (l *tcpListener) Serve(_ context.Context) error {
	l.mu.Lock()
	srv := l.srv
	l.mu.Unlock()
	if srv == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "tcp", "addr", l.addr)
	l.serving.Store(true)
	defer l.serving.Store(false)
	err := srv.ActivateAndServe()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (l *tcpListener) Shutdown(_ context.Context) error {
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

	zlog.Info("DNS server stopping", "net", "tcp", "addr", l.addr)
	// Always close the listener ourselves: miekg/dns's
	// ShutdownContext is a no-op when Serve hasn't started, which is
	// exactly the case bindAll's partial-failure cleanup hits.
	srvErr := srv.ShutdownContext(shutdownCtx)
	if ignoreShutdownErr(srvErr) {
		srvErr = nil
	}
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && srvErr == nil {
			srvErr = err
		}
	}
	return srvErr
}
