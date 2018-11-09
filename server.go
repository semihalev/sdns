package main

import (
	"bufio"
	"crypto/tls"
	"io"
	l "log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/semihalev/sdns/ctx"

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

	rTimeout time.Duration
	wTimeout time.Duration

	handlers []ctx.Handler
	pool     sync.Pool
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
	dc := s.pool.Get().(*ctx.Context)

	dc.ResetHTTP(w, r)
	dc.NextHTTP()

	s.pool.Put(dc)
}

// Run starts the server
func (s *Server) Run() {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	tcpServer := &dns.Server{
		Addr:         s.addr,
		Net:          "tcp",
		Handler:      mux,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
		ReusePort:    true,
	}

	udpServer := &dns.Server{
		Addr:         s.addr,
		Net:          "udp",
		Handler:      mux,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
		ReusePort:    true,
	}

	go listenAndServe(udpServer)
	go listenAndServe(tcpServer)

	if s.tlsAddr != "" {
		cert, err := tls.LoadX509KeyPair(s.tlsCertificate, s.tlsPrivateKey)
		if err != nil {
			log.Crit("TLS certificate load failed", "error", err.Error())
			return
		}

		tlsServer := &dns.Server{
			Addr:         s.tlsAddr,
			Net:          "tcp-tls",
			TLSConfig:    &tls.Config{Certificates: []tls.Certificate{cert}},
			Handler:      mux,
			ReadTimeout:  s.rTimeout,
			WriteTimeout: s.wTimeout,
		}

		go listenAndServe(tlsServer)
	}

	if s.dohAddr != "" {
		logReader, logWriter := io.Pipe()
		go func(rd io.Reader) {
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
		}(logReader)

		srv := &http.Server{
			Addr:         s.dohAddr,
			Handler:      s,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  30 * time.Second,
			ErrorLog:     l.New(logWriter, "", 0),
		}

		go func() {
			log.Info("DNS server listening...", "net", "https", "addr", s.dohAddr)

			if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil {
				log.Crit("DNS listener failed", "net", "https", "addr", s.dohAddr, "error", err.Error())
			}
		}()
	}
}

func listenAndServe(ds *dns.Server) {
	log.Info("DNS server listening...", "net", ds.Net, "addr", ds.Addr)

	if err := ds.ListenAndServe(); err != nil {
		log.Crit("DNS listener failed", "net", ds.Net, "addr", ds.Addr, "error", err.Error())
	}
}
