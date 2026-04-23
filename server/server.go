package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/server/doh"
	"github.com/semihalev/zlog/v2"
)

// Server type.
type Server struct {
	cfg *config.Config

	chainPool   sync.Pool
	certManager *CertManager
	certMu      sync.Mutex

	listenersMu sync.Mutex
	listeners   []Listener
	active      []Listener

	running atomic.Int32
}

// New return new server.
func New(cfg *config.Config) *Server {
	if cfg.Bind == "" {
		cfg.Bind = ":53"
	}

	s := &Server{cfg: cfg}
	s.chainPool.New = func() any {
		return middleware.NewChain(middleware.Handlers())
	}

	timeout := cfg.QueryTimeout.Duration
	s.listeners = []Listener{
		newUDPListener(cfg.Bind, s, timeout),
		newTCPListener(cfg.Bind, s, timeout),
	}
	if cfg.BindTLS != "" {
		s.listeners = append(s.listeners, newTLSListener(cfg.BindTLS, s, s, timeout))
	}
	if cfg.BindDOH != "" {
		s.listeners = append(s.listeners,
			newDOHListener(cfg.BindDOH, s, s, timeout),
			newDOH3Listener(cfg.BindDOH, s, s),
		)
	}
	if cfg.BindDOQ != "" {
		s.listeners = append(s.listeners, newDOQListener(cfg.BindDOQ, s, s))
	}

	return s
}

// (*Server).ServeDNS serveDNS implements the Handle interface.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ch := s.chainPool.Get().(*middleware.Chain)
	defer s.chainPool.Put(ch)

	ch.Reset(w, r)

	ch.Next(context.Background())
}

// ServeHTTP implements http.Handler (DoH + DoH3).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "sdns")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.ProtoMajor < 3 {
		_, port, _ := net.SplitHostPort(s.cfg.BindDOH)
		w.Header().Set("Alt-Svc", `h3=":`+port+`"; ma=2592000`)
	}

	handle := func(req *dns.Msg) *dns.Msg {
		mw := mock.NewWriter("doh", r.RemoteAddr)
		s.ServeDNS(mw, req)
		if !mw.Written() {
			return nil
		}
		return mw.Msg()
	}

	var handlerFn func(http.ResponseWriter, *http.Request)
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handlerFn = doh.HandleJSON(handle)
	} else {
		handlerFn = doh.HandleWireFormat(handle)
	}
	handlerFn(w, r)
}

// Run binds every configured listener synchronously, returns a non-nil
// error if a critical listener (plain DNS UDP/TCP) could not bind, and
// otherwise spawns Serve goroutines that run until ctx is cancelled.
// Run itself is non-blocking — main waits on ctx and polls Stopped
// for graceful shutdown.
func (s *Server) Run(ctx context.Context) error {
	s.listenersMu.Lock()
	listeners := append([]Listener(nil), s.listeners...)
	s.listenersMu.Unlock()

	active, err := bindAll(ctx, listeners)
	if err != nil {
		// An optional TLS / DoH / DoQ bind may have run to completion
		// before the critical failure, which lazily spins up the
		// shared CertManager (fsnotify watcher goroutine + cert
		// reload state). Release it here so the process doesn't leak
		// the watcher after Run returns non-nil.
		s.Stop()
		return err
	}

	s.listenersMu.Lock()
	s.active = active
	s.listenersMu.Unlock()

	for _, l := range active {
		s.running.Add(1)
		go func(l Listener) {
			defer s.running.Add(-1)
			if err := l.Serve(ctx); err != nil {
				zlog.Error("listener stopped with error",
					"proto", l.Proto(), "addr", l.Addr(), "error", err.Error())
			}
		}(l)
	}

	// Supervisor: on ctx cancellation, shut every active listener down.
	go s.superviseShutdown(ctx, active)
	return nil
}

func (s *Server) superviseShutdown(ctx context.Context, active []Listener) {
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout())
	defer cancel()
	for _, l := range active {
		if err := l.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			zlog.Error("listener shutdown failed",
				"proto", l.Proto(), "addr", l.Addr(), "error", err.Error())
		}
	}
}

func (s *Server) shutdownTimeout() time.Duration {
	if t := s.cfg.QueryTimeout.Duration; t > 0 {
		return t
	}
	return 10 * time.Second
}

// HasListener reports whether a listener with the given proto tag is
// actually serving right now — stricter than "Bind succeeded". DoH3
// and DoQ do their real QUIC bring-up inside Serve, so checking only
// membership in s.active can report success even when the transport
// never started. Asking the listener via Serving() gives the truth.
func (s *Server) HasListener(proto string) bool {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	for _, l := range s.active {
		if l.Proto() == proto && l.Serving() {
			return true
		}
	}
	return false
}

// GetTLSConfig satisfies certProvider. It lazily materialises the shared
// CertManager on first TLS listener Bind and hands out its live TLS
// config (with rotation hooks) to each listener that asks.
func (s *Server) GetTLSConfig() *tls.Config {
	s.certMu.Lock()
	defer s.certMu.Unlock()

	if s.certManager != nil {
		return s.certManager.GetTLSConfig()
	}

	if s.cfg.TLSCertificate == "" || s.cfg.TLSPrivateKey == "" {
		return nil
	}

	cm, err := NewCertManager(s.cfg.TLSCertificate, s.cfg.TLSPrivateKey)
	if err != nil {
		zlog.Error("certificate manager init failed", "error", err.Error())
		return nil
	}
	s.certManager = cm
	return cm.GetTLSConfig()
}

// Stopped reports whether every Serve goroutine has exited.
// Used by sdns.go for graceful-shutdown polling.
func (s *Server) Stopped() bool {
	return s.running.Load() == 0
}

// Stop releases long-lived resources (currently just the cert manager).
func (s *Server) Stop() {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if s.certManager != nil {
		s.certManager.Stop()
		s.certManager = nil
	}
}

// ReloadCertificate forces a certificate reload on all TLS listeners.
func (s *Server) ReloadCertificate() error {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if s.certManager == nil {
		return errors.New("no certificate manager configured")
	}
	zlog.Info("Reloading TLS certificate")
	return s.certManager.Reload()
}
