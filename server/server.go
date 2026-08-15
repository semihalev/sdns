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
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/server/doh"
	"github.com/semihalev/zlog/v2"
)

// Server type.
type Server struct {
	cfg      *config.Config
	pipeline *middleware.Pipeline

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

	s := &Server{cfg: cfg, pipeline: middleware.GlobalPipeline()}

	timeout := cfg.QueryTimeout.Duration
	// The owned transports feed ServeRaw: raw bytes in, and the server —
	// not the transport — decides eligibility, decode, and context. DoH
	// and DoQ enter through ServeMsg with a decoded message — one reshapes
	// bytes and the other rewrites the reply ID, so neither is a raw sink.
	s.listeners = []Listener{
		newUDPListener(cfg.Bind, s, timeout, cfg.IngressWorkers, cfg.IngressQueue),
		newTCPListener(cfg.Bind, s, timeout, cfg.IngressTCPConns),
	}
	if cfg.BindTLS != "" {
		s.listeners = append(s.listeners, newTLSListener(cfg.BindTLS, s, s, timeout, cfg.IngressTCPConns))
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

// ServeMsg serves one decoded DNS request under the transport's lifetime
// and the configured end-to-end middleware/resolution timeout. It is the
// entry for transports that already hold a message — DNS-over-HTTP and
// DNS-over-QUIC supply client-aware parents — and for embedders. Its
// writers made no byte-sink promise, so they never receive raw packed
// bytes; the owned raw transports enter through ServeRaw instead, which is
// the one road to the direct-pack capability.
func (s *Server) ServeMsg(parent context.Context, w middleware.Transport, r *dns.Msg) {
	s.serveMsg(parent, w, r, false)
}

func (s *Server) serveMsg(parent context.Context, w middleware.Transport, r *dns.Msg, directPack bool) {
	s.serveMsgBy(parent, w, r, directPack, time.Now().Add(s.queryTimeout()))
}

// serveMsgBy is serveMsg with the deadline stated rather than started
// here. The raw ingress passes one anchored at the packet's arrival, so
// a query that has already spent part of its budget waiting for a slab
// does not get a fresh full budget the moment it leaves the byte path —
// under saturation that is exactly the query that would hold a worker
// and an upstream lookup longest, and precisely when neither can spare
// it. Callers with no arrival time (the decoded-message API) start the
// clock at the call.
func (s *Server) serveMsgBy(
	parent context.Context, w middleware.Transport, r *dns.Msg,
	directPack bool, deadline time.Time,
) {
	if parent == nil {
		parent = context.Background()
	}
	ctx := contextutil.WithLazyDeadline(parent, deadline)
	defer ctx.Cancel()
	if contextutil.EffectiveError(ctx) != nil {
		return
	}

	// A standard query carries exactly one question. Reject a malformed
	// QDCOUNT here — at the single entry shared by every transport — with
	// FORMERR, so downstream middlewares can index req.Question[0] without
	// guarding. A 0-question packet would otherwise hit an unguarded
	// req.Question[0] in several handlers and force a panic/recover/log
	// cycle per packet (a cheap amplification vector that also pollutes
	// the panic metric).
	if len(r.Question) != 1 {
		formerr := new(dns.Msg)
		formerr.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(formerr)
		return
	}

	if s.pipeline == nil {
		servfail := new(dns.Msg)
		servfail.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(servfail)
		return
	}

	ch := s.pipeline.NewChain()
	defer s.pipeline.PutChain(ch)

	ch.Reset(w, r)
	if directPack {
		ch.AllowDirectPack()
	}
	ch.Next(ctx)
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
		s.ServeMsg(r.Context(), mw, req)
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
				recordListenerErr(l.Proto())
				zlog.Error("listener stopped with error",
					"proto", l.Proto(), "addr", l.Addr(), "error", err.Error())
			}
		}(l)
	}

	// Supervisor: on ctx cancellation, shut every active listener down.
	go s.superviseShutdown(ctx, active) //nolint:gosec // G118 — ctx is the server lifecycle context, not request-scoped
	return nil
}

func (s *Server) superviseShutdown(ctx context.Context, active []Listener) {
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout())
	defer cancel()

	// All at once, on one shared deadline. Taken in turn, every listener
	// after the first keeps admitting work — new connections, new queries
	// — for as long as the ones ahead of it take to drain, which is the
	// opposite of what a shutdown is for. Each listener stops its own
	// admission before it drains, so starting them together closes the
	// door everywhere first.
	var wg sync.WaitGroup
	for _, l := range active {
		wg.Add(1)
		go func(l Listener) {
			defer wg.Done()
			if err := l.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
				zlog.Error("listener shutdown failed",
					"proto", l.Proto(), "addr", l.Addr(), "error", err.Error())
			}
		}(l)
	}
	wg.Wait()
}

func (s *Server) shutdownTimeout() time.Duration {
	return s.queryTimeout()
}

func (s *Server) queryTimeout() time.Duration {
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
// Quiesced reports whether every owned transport has all of its job
// slabs back in the ring: nothing is being read into, served, or staged
// for a send.
//
// It is the completion barrier a measurement needs. A client holding its
// last reply proves the bytes left, not that the slab that carried them
// was released — the release runs after the send, on the server's own
// goroutine — so anything that samples the process at that moment (an
// allocation gate, a leak check, a drain assertion) is otherwise reduced
// to sleeping and hoping. Transports that own no slabs are quiescent by
// construction and answer for themselves.
func (s *Server) Quiesced() bool {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	for _, l := range s.active {
		if q, ok := l.(interface{ Quiesced() bool }); ok && !q.Quiesced() {
			return false
		}
	}
	return true
}

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
