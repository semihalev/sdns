package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/semihalev/zlog/v2"
)

func zlogListenerDisabled(l Listener, err error) {
	zlog.Error("listener disabled", "proto", l.Proto(), "addr", l.Addr(), "error", err.Error())
}

// Listener is the lifecycle contract for a single DNS service endpoint
// (UDP, TCP, DoT, DoH, DoH3, DoQ). It separates bind from serve so that
// the Server can fail fast on port-in-use, missing cert, etc. instead of
// swallowing the error inside a background goroutine.
//
// Lifecycle: Bind → Serve → Shutdown. Bind may be called at most once.
// Serve returns when Shutdown is called or the underlying socket closes.
// Shutdown is idempotent.
type Listener interface {
	// Proto returns the transport tag, "udp", "tcp", "tls", "doh",
	// "doh3", "doq", used for logging and metrics.
	Proto() string

	// Addr returns the configured bind address.
	Addr() string

	// Bind acquires the underlying socket (and any TLS material it
	// needs) synchronously. A non-nil return means the listener is
	// not ready to serve.
	Bind(ctx context.Context) error

	// Serve blocks until Shutdown is called or the socket is closed.
	// It must only be called after a successful Bind.
	Serve(ctx context.Context) error

	// Shutdown releases the underlying socket. Safe to call before
	// Serve or after Serve has already returned.
	Shutdown(ctx context.Context) error

	// Critical reports whether a Bind failure on this listener should
	// abort server startup. Plain DNS (UDP+TCP on cfg.Bind) is
	// critical; optional services (TLS, DoH, DoH3, DoQ) are not,
	// a missing cert or misconfigured addr only disables that service.
	Critical() bool

	// Serving reports whether the Serve loop is currently active.
	// This is stricter than "Bind succeeded": QUIC-based listeners
	// (DoH3, DoQ) complete their real startup inside Serve, so a
	// listener can be bound but not actually serving if Serve
	// returned an error during its own setup phase.
	Serving() bool
}

// errListenerNotBound is returned from Serve when called before Bind.
var errListenerNotBound = errors.New("listener: Serve called before Bind")

// listenTCPAll opens a TCP listener on every address or on none: a failure
// closes what was already open and names the address that failed. wrap, when
// set, wraps each one (TLS).
func listenTCPAll(ctx context.Context, addrs []string, wrap func(net.Listener) net.Listener) ([]net.Listener, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no address")
	}
	var lc net.ListenConfig
	lns := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			for _, open := range lns {
				_ = open.Close()
			}
			return nil, fmt.Errorf("%s: %w", addr, err)
		}
		if wrap != nil {
			ln = wrap(ln)
		}
		lns = append(lns, ln)
	}
	return lns, nil
}

// listenUDPAll is listenTCPAll for the packet sockets QUIC runs over.
func listenUDPAll(ctx context.Context, addrs []string) ([]net.PacketConn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no address")
	}
	var lc net.ListenConfig
	pcs := make([]net.PacketConn, 0, len(addrs))
	for _, addr := range addrs {
		pc, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			for _, open := range pcs {
				_ = open.Close()
			}
			return nil, fmt.Errorf("%s: %w", addr, err)
		}
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

// bindAll runs Bind on every listener and collects the outcome.
// Non-critical bind failures disable that listener (its Serve becomes
// a no-op) but do not abort startup; critical failures are returned as
// a single joined error so main can log them and exit non-zero.
//
// When a critical failure is present, listeners that already bound
// successfully are shut down before bindAll returns, so the caller
// never has to remember half-bound state. The invariant is
// "err != nil ⇒ no sockets held by this resolver".
func bindAll(ctx context.Context, listeners []Listener) ([]Listener, error) {
	var active []Listener
	var criticalErrs []error
	for _, l := range listeners {
		if bindErr := l.Bind(ctx); bindErr != nil {
			if l.Critical() {
				criticalErrs = append(criticalErrs,
					fmt.Errorf("%s %s: %w", l.Proto(), l.Addr(), bindErr))
				continue
			}
			zlogListenerDisabled(l, bindErr)
			continue
		}
		active = append(active, l)
	}
	if len(criticalErrs) > 0 {
		// Undo the successful binds so the process doesn't leak FDs
		// (UDP bound, TCP failed is the typical case).
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, l := range active {
			_ = l.Shutdown(shutdownCtx)
		}
		return nil, errors.Join(criticalErrs...)
	}
	return active, nil
}
