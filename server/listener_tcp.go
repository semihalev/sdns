package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/semihalev/zlog/v2"
)

// tcpListener runs the owned TCP engine (tcp_engine.go): an accept loop
// admitting up to the configured connection cap, per-connection goroutines
// with the handler inline, prefix-first job acquisition from a shared
// large-class ring. Several addresses are one accept loop each over the one
// engine, so the connection cap is the transport's, not an address's.
type tcpListener struct {
	addrs    []string
	handler  rawHandler
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

func newTCPListener(addrs []string, h rawHandler, timeout time.Duration, maxConns int, plan resourcePlan) *tcpListener {
	return &tcpListener{addrs: addrs, handler: h, timeout: timeout, maxConns: maxConns, plan: plan}
}

func (l *tcpListener) Proto() string  { return "tcp" }
func (l *tcpListener) Addr() string   { return strings.Join(l.addrs, ", ") }
func (l *tcpListener) Critical() bool { return true }
func (l *tcpListener) Serving() bool  { return l.serving.Load() }

// Quiesced reports whether the engine holds no in-flight work.
func (l *tcpListener) Quiesced() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.engine == nil || l.engine.quiesced()
}

func (l *tcpListener) Bind(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lns != nil {
		return errors.New("tcp listener: Bind called twice")
	}
	lns, err := listenTCPAll(ctx, l.addrs, nil)
	if err != nil {
		return err
	}
	l.lns = lns
	l.engine = newTCPEngine(l.handler, "tcp", l.maxConns, l.plan)
	l.done = make(chan struct{})
	return nil
}

func (l *tcpListener) Serve(_ context.Context) error {
	l.mu.Lock()
	lns, engine, done := l.lns, l.engine, l.done
	l.mu.Unlock()
	if lns == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "tcp", "addr", l.Addr(),
		"maxconns", engine.maxConns, "smalljobs", cap(engine.smallTokens), "largejobs", cap(engine.largeTokens))
	l.serving.Store(true)
	defer l.serving.Store(false)

	for _, ln := range lns {
		addr := ln.Addr().String()
		if !engine.startAccepting(ln, func() {
			if !l.closing.Load() {
				zlog.Error("TCP accept loop exited outside shutdown", "addr", addr)
				recordListenerErr("tcp")
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

func (l *tcpListener) Shutdown(_ context.Context) error {
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
		zlog.Info("DNS server stopping", "net", "tcp", "addr", l.Addr())

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

// TrimIdleMemory drops the engine's parked slabs (see trim.go).
func (l *tcpListener) TrimIdleMemory() int {
	l.mu.Lock()
	engine := l.engine
	l.mu.Unlock()
	if engine == nil {
		return 0
	}
	return engine.trimIdle()
}
