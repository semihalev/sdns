package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/semihalev/zlog/v2"
)

// dohListener serves DNS-over-HTTPS (RFC 8484). Non-critical. Several
// addresses are one HTTP server serving each of their sockets.
type dohListener struct {
	addrs   []string
	handler http.Handler
	certs   certProvider
	timeout time.Duration

	mu        sync.Mutex
	srv       *http.Server
	lns       []net.Listener
	logCloser io.Closer
	serving   atomic.Bool
}

func newDOHListener(addrs []string, h http.Handler, certs certProvider, timeout time.Duration) *dohListener {
	return &dohListener{addrs: addrs, handler: h, certs: certs, timeout: timeout}
}

func (d *dohListener) Proto() string  { return "doh" }
func (d *dohListener) Addr() string   { return strings.Join(d.addrs, ", ") }
func (d *dohListener) Critical() bool { return false }
func (d *dohListener) Serving() bool  { return d.serving.Load() }

func (d *dohListener) Bind(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.srv != nil {
		return errors.New("doh listener: Bind called twice")
	}
	if d.certs == nil {
		return errors.New("no TLS certificate configured")
	}
	tlsConfig := d.certs.GetTLSConfig()
	if tlsConfig == nil {
		return errors.New("TLS certificate not available")
	}

	lns, err := listenTCPAll(ctx, d.addrs, nil)
	if err != nil {
		return err
	}

	// Reroute http.Server's internal error logging through zlog so we
	// don't dump bare stderr lines on request errors.
	logReader, logWriter := io.Pipe()
	go readHTTPServerLogs(logReader)

	d.lns = lns
	d.logCloser = logReader
	d.srv = &http.Server{
		Handler: d.handler,
		// ReadHeaderTimeout bounds slow-loris style attacks that
		// trickle request headers. DoH headers are small, anything
		// legitimate arrives well under 5s.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		// Bound per-connection keep-alive dwell time so stale DoH
		// connections don't hoard file descriptors.
		IdleTimeout: 2 * time.Minute,
		// DoH request headers are tiny; Go's default 1 MiB cap is
		// absurd for the shape of traffic we expect. 16 KiB fits
		// every reasonable DoH GET/POST header and stops header-
		// bomb probes.
		MaxHeaderBytes: 16 << 10,
		ErrorLog:       stdlog.New(logWriter, "", 0),
		TLSConfig:      tlsConfig,
	}
	return nil
}

func (d *dohListener) Serve(_ context.Context) error {
	d.mu.Lock()
	srv, lns := d.srv, d.lns
	d.mu.Unlock()
	if srv == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "doh", "addr", d.Addr())
	d.serving.Store(true)
	defer d.serving.Store(false)
	// Empty cert/key paths: srv.TLSConfig.GetCertificate handles rotation.
	// One server serves every socket, and Shutdown ends them all.
	errs := make(chan error, len(lns))
	for _, ln := range lns {
		go func() { errs <- srv.ServeTLS(ln, "", "") }()
	}
	var serveErr error
	for range lns {
		if err := <-errs; err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			serveErr = errors.Join(serveErr, err)
		}
	}
	return serveErr
}

func (d *dohListener) Shutdown(_ context.Context) error {
	d.mu.Lock()
	srv := d.srv
	lns := d.lns
	lc := d.logCloser
	d.mu.Unlock()
	if srv == nil {
		return nil
	}

	timeout := d.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	zlog.Info("DNS server stopping", "net", "doh", "addr", d.Addr())
	// http.Server.Shutdown only closes listeners that were
	// registered with it via Serve / ServeTLS (trackListener).
	// Our listeners are pre-bound in Bind and aren't handed to ServeTLS
	// until Serve runs, so in the bind-before-serve rollback path
	// (bindAll partial-failure cleanup) they would stay open. Close
	// them ourselves; net.ErrClosed is the normal-close race when
	// Serve did run.
	err := srv.Shutdown(shutdownCtx)
	for _, ln := range lns {
		if cerr := ln.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
			err = cerr
		}
	}
	if lc != nil {
		_ = lc.Close()
	}
	return err
}

// readHTTPServerLogs reroutes http.Server's internal error log through
// zlog at warn level, matching the pre-refactor behaviour.
func readHTTPServerLogs(r io.Reader) {
	buf := bufio.NewReader(r)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil {
			return
		}
		parts := strings.SplitN(string(line[:len(line)-1]), " ", 2)
		if len(parts) > 1 {
			zlog.Warn("Client http socket failed", "net", "https", "error", parts[1])
		}
	}
}
