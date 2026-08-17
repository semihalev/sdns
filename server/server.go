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
	// replay is the pipeline minus every OncePerQuery handler: the chain
	// a worker runs for a query the inline pass admitted, guarded, and
	// then handed off unwritten. Entry-effect middlewares already fired
	// on the inline pass; response-keyed ones fire here, once, when the
	// replay writes.
	replay *middleware.Pipeline

	certManager *CertManager
	certMu      sync.Mutex

	listenersMu sync.Mutex
	listeners   []Listener
	active      []Listener
	// shutdownDone closes when the shutdown supervisor has finished with
	// every listener. Serve goroutines exiting is not the same event: a
	// QUIC listener's accept loop returns the moment its server stops
	// accepting, while the socket it was handed is closed a few
	// statements later, by the supervisor.
	shutdownDone chan struct{}
	// trimDone closes when the opt-in trimmer goroutine has exited; nil
	// when it was never started. Stopped waits on it — a trim is a
	// process-wide collection, and "stopped" must not be true while one
	// may still be running.
	trimDone chan struct{}

	// served counts queries entering either serve entry point, whatever
	// transport carried them — the owned engines through ServeRaw, DoH,
	// DoH3 and DoQ through ServeMsg. The trimmer reads it to prove a
	// window carried no traffic at all: the engines' own counters see
	// only their transports, and a trim under active DoH traffic is a
	// collection the client pays for. Counted only when the trimmer —
	// its one reader — exists, so the default configuration pays not
	// even the atomic.
	served      atomic.Uint64
	trimEnabled bool

	running atomic.Int32

	// certStopped marks the certificate provider closed: Stop has run,
	// and no caller may lazily create a new manager (and its watcher).
	// Guarded by certMu.
	certStopped bool
}

// New return new server.
func New(cfg *config.Config) *Server {
	if cfg.Bind == "" {
		cfg.Bind = ":53"
	}

	s := &Server{cfg: cfg, pipeline: middleware.GlobalPipeline(), trimEnabled: cfg.MemoryTrim}
	if s.pipeline != nil {
		var once []string
		for _, h := range s.pipeline.Handlers() {
			if o, ok := h.(middleware.OncePerQuery); ok && o.OncePerQuery() {
				once = append(once, h.Name())
			}
		}
		s.replay = s.pipeline.SubPipeline(once...)
	}

	// One resource plan for every listener, derived before any exists:
	// the stream engines share a budget, so the plan has to know how
	// many there are. The plan is a value on this Server — a second
	// Server in the same process lives inside its own arithmetic.
	engines := 1
	if cfg.BindTLS != "" {
		engines = 2
	}
	plan := defaultResourcePlan(engines)
	plan.publish()

	timeout := cfg.QueryTimeout.Duration
	// The owned transports feed ServeRaw: raw bytes in, and the server —
	// not the transport — decides eligibility, decode, and context. DoH
	// and DoQ enter through ServeMsg with a decoded message — one reshapes
	// bytes and the other rewrites the reply ID, so neither is a raw sink.
	s.listeners = []Listener{
		newUDPListener(cfg.Bind, s, timeout, cfg.IngressWorkers, cfg.IngressQueue, plan),
		newTCPListener(cfg.Bind, s, timeout, cfg.IngressTCPConns, plan),
	}
	if cfg.BindTLS != "" {
		s.listeners = append(s.listeners, newTLSListener(cfg.BindTLS, s, s, timeout, cfg.IngressTCPConns, plan))
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

// ServeDNS keeps *Server a dns.Handler for embedders: the rewrite moved
// the owned transports off this entry, but code that mounts a Server
// under the library's mux did not change. A dns.ResponseWriter is a
// Transport already; nothing here is on the serving path.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.ServeMsg(context.Background(), w, r)
}

// ServeDNSContext is ServeDNS with a caller-owned parent context, kept
// for the same embedders.
func (s *Server) ServeDNSContext(parent context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if parent == nil {
		parent = context.Background()
	}
	s.ServeMsg(parent, w, r)
}

func (s *Server) serveMsg(parent context.Context, w middleware.Transport, r *dns.Msg, directPack bool) {
	if s.trimEnabled {
		s.served.Add(1)
	}
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

	done := make(chan struct{})
	s.listenersMu.Lock()
	s.active = active
	s.shutdownDone = done
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
	go s.superviseShutdown(ctx, active, done) //nolint:gosec // G118 — ctx is the server lifecycle context, not request-scoped
	if s.cfg.MemoryTrim {
		trimDone := make(chan struct{})
		s.listenersMu.Lock()
		s.trimDone = trimDone
		s.listenersMu.Unlock()
		go func() { //nolint:gosec // G118 — same lifecycle context
			defer close(trimDone)
			s.trimLoop(ctx)
		}()
	}
	return nil
}

func (s *Server) superviseShutdown(ctx context.Context, active []Listener, done chan struct{}) {
	defer close(done)
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

	// The certificate watcher belongs to the run it served: a cancelled
	// context must tear it down with the listeners, or every restart
	// leaves a file watcher rescanning a directory nobody serves from.
	// Stop is idempotent through the nil check it makes under its lock.
	s.Stop()
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

	// The lazy creation below is for startup. After Stop it would leave
	// a file watcher alive behind a Stopped() that already said true —
	// the defence in depth for any caller still holding this provider.
	if s.certStopped {
		return nil
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

// Stopped reports whether the shutdown is complete: every Serve goroutine
// has exited *and* the supervisor has finished with every listener. That
// is the question a caller polling for shutdown actually has, because the
// only use for the answer is doing something else with what the server
// held — exiting, or binding the same addresses again.
//
// Both halves are needed. The plain UDP and TCP listeners close their
// sockets inside Shutdown before the Serve they unblock returns, so for
// them the goroutine count alone would do. QUIC does not work that way:
// http3 and DoQ hand their accept loop a PacketConn they do not own, so
// Serve returns as soon as the server stops accepting while the socket
// stays open until the supervisor closes it a few statements later. A
// caller that rebound on the goroutine count alone met "address already
// in use", rarely for DoH3 and often for DoQ.
//
// It does not mean nothing is running. A handler that outlasts its
// listener's drain deadline is force-closed and left to finish on its own
// — the alternative is a shutdown that a single stuck request can hang
// forever — so work can outlive this by as long as that handler takes.
// Process exit is the backstop for that, and an in-process restart is
// safe from the socket's point of view but not a guarantee that the old
// server's last requests have unwound.
func (s *Server) Stopped() bool {
	if s.running.Load() != 0 {
		return false
	}
	s.listenersMu.Lock()
	done := s.shutdownDone
	trimDone := s.trimDone
	s.listenersMu.Unlock()
	if trimDone != nil {
		select {
		case <-trimDone:
		default:
			return false
		}
	}
	if done == nil {
		// Run never got as far as arming a supervisor: nothing was ever
		// bound, so nothing is held.
		return true
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// Stop releases long-lived resources (currently just the cert manager).
func (s *Server) Stop() {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	s.certStopped = true
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
