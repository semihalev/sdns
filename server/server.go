package server

import (
	"bufio"
	"context"
	"io"
	l "log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/server/doh"
	"github.com/semihalev/sdns/server/doq"
)

// Server type
type Server struct {
	addr           string
	tlsAddr        string
	dohAddr        string
	doqAddr        string
	tlsCertificate string
	tlsPrivateKey  string

	srvhttp  *http.Server
	srvhttp3 *http3.Server

	chainPool sync.Pool
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
	}

	server.chainPool.New = func() interface{} {
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

	if s.srvhttp3 != nil {
		if r.ProtoMajor < 3 {
			s.srvhttp3.SetQuicHeaders(w.Header())
		}
	}

	handle := func(req *dns.Msg) *dns.Msg {
		mw := mock.NewWriter("tcp", r.RemoteAddr)
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
func (s *Server) Run() {
	go s.ListenAndServeDNS("udp")
	go s.ListenAndServeDNS("tcp")
	go s.ListenAndServeDNSTLS()
	go s.ListenAndServeHTTPTLS()
	go s.ListenAndServeH3()
	go s.ListenAndServeQUIC()
}

// ListenAndServeDNS Starts a server on address and network specified Invoke handler
// for incoming queries.
func (s *Server) ListenAndServeDNS(network string) {
	log.Info("DNS server listening...", "net", network, "addr", s.addr)

	server := &dns.Server{
		Addr:          s.addr,
		Net:           network,
		Handler:       s,
		MaxTCPQueries: 2048,
		ReusePort:     true,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Error("DNS listener failed", "net", network, "addr", s.addr, "error", err.Error())
	}
}

// ListenAndServeDNSTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeDNSTLS() {
	if s.tlsAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "tcp-tls", "addr", s.tlsAddr)

	if err := dns.ListenAndServeTLS(s.tlsAddr, s.tlsCertificate, s.tlsPrivateKey, s); err != nil {
		log.Error("DNS listener failed", "net", "tcp-tls", "addr", s.tlsAddr, "error", err.Error())
	}
}

// ListenAndServeHTTPTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeHTTPTLS() {
	if s.dohAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "doh", "addr", s.dohAddr)

	logReader, logWriter := io.Pipe()
	go readlogs(logReader)

	srv := &http.Server{
		Addr:         s.dohAddr,
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ErrorLog:     l.New(logWriter, "", 0),
	}

	s.srvhttp = srv

	if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil {
		log.Error("DNSs listener failed", "net", "doh", "addr", s.dohAddr, "error", err.Error())
	}
}

// ListenAndServeH3
func (s *Server) ListenAndServeH3() {
	if s.dohAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "h3", "addr", s.dohAddr)

	srv := &http3.Server{
		Addr:    s.dohAddr,
		Handler: s,
		QuicConfig: &quic.Config{
			Allow0RTT: true,
		},
	}

	s.srvhttp3 = srv

	if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil {
		log.Error("DNSs listener failed", "net", "h3", "addr", s.dohAddr, "error", err.Error())
	}
}

// ListenAndServeQUIC
func (s *Server) ListenAndServeQUIC() {
	if s.doqAddr == "" {
		return
	}

	srv := &doq.Server{
		Addr:    s.doqAddr,
		Handler: s,
	}

	log.Info("DNS server listening...", "net", "doq", "addr", s.doqAddr)

	if err := srv.ListenAndServeQUIC(s.tlsCertificate, s.tlsPrivateKey); err != nil {
		log.Error("DNSs listener failed", "net", "doq", "addr", s.doqAddr, "error", err.Error())
	}
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
			log.Warn("Client http socket failed", "net", "https", "error", parts[1])
		}
	}
}
