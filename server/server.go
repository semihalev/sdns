package server

import (
	"bufio"
	"io"
	l "log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/doh"
	"github.com/semihalev/sdns/mock"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Server type
type Server struct {
	addr           string
	tlsAddr        string
	dohAddr        string
	tlsCertificate string
	tlsPrivateKey  string

	handlers []ctx.Handler
	pool     sync.Pool
}

// New return new server
func New(cfg *config.Config) *Server {
	server := &Server{
		addr:           cfg.Bind,
		tlsAddr:        cfg.BindTLS,
		dohAddr:        cfg.BindDOH,
		tlsCertificate: cfg.TLSCertificate,
		tlsPrivateKey:  cfg.TLSPrivateKey,
	}

	server.pool.New = func() interface{} {
		return ctx.New(server.handlers)
	}

	dns.Handle(".", server)

	return server
}

// Register middleware
func (s *Server) Register(h ctx.Handler) {
	s.handlers = append(s.handlers, h)
	log.Info("Register middleware", "name", h.Name())
}

// ServeDNS implements the Handle interface.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	dc := s.pool.Get().(*ctx.Context)

	dc.ResetDNS(w, r)
	dc.NextDNS()

	s.pool.Put(dc)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handle := func(Net string, req *dns.Msg) *dns.Msg {
		mw := mock.NewWriter(Net, r.RemoteAddr)
		s.ServeDNS(mw, req)

		if !mw.Written() {
			return nil
		}

		return mw.Msg()
	}

	var f func(http.ResponseWriter, *http.Request) bool
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		f = doh.HandleJSON(handle)
	} else {
		f = doh.HandleWireFormat(handle)
	}

	if f(w, r) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

// Run listen the services
func (s *Server) Run() {
	go s.ListenAndServeDNS("udp")
	go s.ListenAndServeDNS("tcp")
	go s.ListenAndServeDNSTLS()
	go s.ListenAndServeHTTPTLS()
}

// ListenAndServeDNS Starts a server on address and network specified Invoke handler
// for incoming queries.
func (s *Server) ListenAndServeDNS(network string) {
	log.Info("DNS server listening...", "net", network, "addr", s.addr)

	if err := dns.ListenAndServe(s.addr, network, dns.DefaultServeMux); err != nil {
		log.Error("DNS listener failed", "net", network, "addr", s.addr, "error", err.Error())
	}
}

// ListenAndServeDNSTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeDNSTLS() {
	if s.tlsAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "tcp-tls", "addr", s.tlsAddr)

	if err := dns.ListenAndServeTLS(s.tlsAddr, s.tlsCertificate, s.tlsPrivateKey, dns.DefaultServeMux); err != nil {
		log.Error("DNS listener failed", "net", "tcp-tls", "addr", s.tlsAddr, "error", err.Error())
	}
}

// ListenAndServeHTTPTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeHTTPTLS() {
	if s.dohAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "https", "addr", s.dohAddr)

	logReader, logWriter := io.Pipe()
	go readlogs(logReader)

	srv := &http.Server{
		Addr:         s.dohAddr,
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ErrorLog:     l.New(logWriter, "", 0),
	}

	if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil {
		log.Error("DNSs listener failed", "net", "https", "addr", s.dohAddr, "error", err.Error())
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
