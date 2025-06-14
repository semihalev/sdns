package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	l "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/server/doh"
	"github.com/semihalev/sdns/server/doq"
	"github.com/semihalev/zlog"
)

// Server type
type Server struct {
	addr           string
	tlsAddr        string
	dohAddr        string
	doqAddr        string
	tlsCertificate string
	tlsPrivateKey  string

	udpStarted  bool
	tcpStarted  bool
	tlsStarted  bool
	dohStarted  bool
	doh3Started bool
	doqStarted  bool

	chainPool sync.Pool
	cfg       *config.Config
}

// New return new server
func New(cfg *config.Config) *Server {
	if cfg.Bind == "" {
		cfg.Bind = ":53"
	}

	server := &Server{
		addr:           cfg.Bind,
		tlsAddr:        cfg.BindTLS,
		dohAddr:        cfg.BindDOH,
		doqAddr:        cfg.BindDOQ,
		tlsCertificate: cfg.TLSCertificate,
		tlsPrivateKey:  cfg.TLSPrivateKey,
		cfg:            cfg,
	}

	server.chainPool.New = func() any {
		return middleware.NewChain(middleware.Handlers())
	}

	return server
}

// ServeDNS implements the Handle interface.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ch := s.chainPool.Get().(*middleware.Chain)
	defer s.chainPool.Put(ch)

	ch.Reset(w, r)

	ch.Next(context.Background())
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Server", "sdns")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.ProtoMajor < 3 {
		_, port, _ := net.SplitHostPort(s.dohAddr)
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

// Run listen the services
func (s *Server) Run(ctx context.Context) {
	go s.ListenAndServeDNS(ctx, "udp")
	go s.ListenAndServeDNS(ctx, "tcp")
	go s.ListenAndServeDNSTLS(ctx)
	go s.ListenAndServeHTTPTLS(ctx)
	go s.ListenAndServeH3(ctx)
	go s.ListenAndServeQUIC(ctx)
}

// ListenAndServeDNS Starts a server on address and network specified Invoke handler
// for incoming queries.
func (s *Server) ListenAndServeDNS(ctx context.Context, network string) error {
	zlog.Info("DNS server listening...", "net", network, "addr", s.addr)

	srv := &dns.Server{
		Addr:          s.addr,
		Net:           network,
		Handler:       s,
		MaxTCPQueries: 2048,
		ReusePort:     true,
	}

	if network == "tcp" {
		s.tcpStarted = true
	} else {
		s.udpStarted = true
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if network == "tcp" {
				s.tcpStarted = false
			} else {
				s.udpStarted = false
			}
			zlog.Error("DNS listener failed", "net", network, "addr", s.addr, "error", err.Error())
		}
	}()

	<-ctx.Done()

	zlog.Info("DNS server stopping...", "net", network, "addr", s.addr)

	dnsCtx, cancel := context.WithTimeout(context.Background(), s.cfg.QueryTimeout.Duration)
	defer cancel()

	if err := srv.ShutdownContext(dnsCtx); err != nil {
		zlog.Error("Shutdown dns server failed:", "net", network, "addr", s.addr, "error", err.Error())
	}

	if network == "tcp" {
		s.tcpStarted = false
	} else {
		s.udpStarted = false
	}

	return nil
}

// ListenAndServeDNSTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeDNSTLS(ctx context.Context) error {
	if s.tlsAddr == "" {
		return nil
	}

	zlog.Info("DNS server listening...", "net", "tls", "addr", s.tlsAddr)

	cert, err := tls.LoadX509KeyPair(s.tlsCertificate, s.tlsPrivateKey)
	if err != nil {
		zlog.Error("DNS listener failed", "net", "tls", "addr", s.tlsAddr, "error", err.Error())
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	srv := &dns.Server{
		Addr:          s.tlsAddr,
		Net:           "tcp-tls",
		Handler:       s,
		MaxTCPQueries: 2048,
		ReusePort:     true,
		TLSConfig:     tlsConfig,
	}

	s.tlsStarted = true

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			s.tlsStarted = false
			zlog.Error("DNS listener failed", "net", "tls", "addr", s.tlsAddr, "error", err.Error())
		}
	}()

	<-ctx.Done()

	zlog.Info("DNS server stopping...", "net", "tls", "addr", s.tlsAddr)

	dnsCtx, cancel := context.WithTimeout(context.Background(), s.cfg.QueryTimeout.Duration)
	defer cancel()

	if err := srv.ShutdownContext(dnsCtx); err != nil {
		zlog.Error("Shutdown dns server failed:", "net", "tls", "addr", s.tlsAddr, "error", err.Error())
	}

	s.tlsStarted = false

	return nil
}

// ListenAndServeHTTPTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeHTTPTLS(ctx context.Context) error {
	if s.dohAddr == "" {
		return nil
	}

	zlog.Info("DNS server listening...", "net", "doh", "addr", s.dohAddr)

	logReader, logWriter := io.Pipe()
	go readlogs(logReader)

	srv := &http.Server{
		Addr:         s.dohAddr,
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ErrorLog:     l.New(logWriter, "", 0),
	}

	s.dohStarted = true

	go func() {
		if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.dohStarted = false
			zlog.Error("DNS listener failed", "net", "doh", "addr", s.dohAddr, "error", err.Error())
		}
	}()

	<-ctx.Done()

	zlog.Info("DNS server stopping...", "net", "doh", "addr", s.dohAddr)

	dohCtx, cancel := context.WithTimeout(context.Background(), s.cfg.QueryTimeout.Duration)
	defer cancel()

	if err := srv.Shutdown(dohCtx); err != nil {
		zlog.Error("Shutdown dns server failed:", "net", "doh", "addr", s.dohAddr, "error", err.Error())
	}

	s.dohStarted = false

	return nil
}

// ListenAndServeH3
func (s *Server) ListenAndServeH3(ctx context.Context) error {
	if s.dohAddr == "" {
		return nil
	}

	zlog.Info("DNS server listening...", "net", "doh-h3", "addr", s.dohAddr)

	srv := &http3.Server{
		Addr:    s.dohAddr,
		Handler: s,
		QUICConfig: &quic.Config{
			Allow0RTT: true,
		},
	}

	s.doh3Started = true

	go func() {
		if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.doh3Started = false
			zlog.Error("DNS listener failed", "net", "doh-h3", "addr", s.dohAddr, "error", err.Error())
		}
	}()

	<-ctx.Done()

	zlog.Info("DNS server stopping...", "net", "doh-h3", "addr", s.dohAddr)

	if err := srv.Close(); err != nil {
		zlog.Error("Shutdown dns server failed:", "net", "doh-h3", "addr", s.dohAddr, "error", err.Error())
	}

	s.doh3Started = false

	return nil
}

// ListenAndServeQUIC
func (s *Server) ListenAndServeQUIC(ctx context.Context) error {
	if s.doqAddr == "" {
		return nil
	}

	srv := &doq.Server{
		Addr:    s.doqAddr,
		Handler: s,
	}

	zlog.Info("DNS server listening...", "net", "doq", "addr", s.doqAddr)

	s.doqStarted = true

	go func() {
		if err := srv.ListenAndServeQUIC(s.tlsCertificate, s.tlsPrivateKey); err != nil && !errors.Is(err, quic.ErrServerClosed) {
			s.doqStarted = false
			zlog.Error("DNS listener failed", "net", "doq", "addr", s.doqAddr, "error", err.Error())
		}
	}()

	<-ctx.Done()

	zlog.Info("DNS server stopping...", "net", "doq", "addr", s.doqAddr)

	if err := srv.Shutdown(); err != nil {
		zlog.Error("Shutdown dns server failed:", "net", "doq", "addr", s.doqAddr, "error", err.Error())
	}

	s.doqStarted = false

	return nil
}

func (s *Server) Stopped() bool {
	if s.udpStarted || s.tcpStarted || s.tlsStarted || s.dohStarted || s.doh3Started || s.doqStarted {
		return false
	}

	return true
}

func readlogs(rd io.Reader) {
	buf := bufio.NewReader(rd)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil {
			continue
		}

		parts := strings.SplitN(string(line[:len(line)-1]), " ", 2)
		if len(parts) > 1 {
			zlog.Warn("Client http socket failed", "net", "https", "error", parts[1])
		}
	}
}
