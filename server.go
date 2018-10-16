package main

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Server type
type Server struct {
	host string

	tlsHost        string
	dohHost        string
	tlsCertificate string
	tlsPrivateKey  string

	rTimeout time.Duration
	wTimeout time.Duration
}

// Run starts the server
func (s *Server) Run() {
	handler := NewHandler()

	tcpHandler := dns.NewServeMux()
	tcpHandler.HandleFunc(".", handler.TCP)

	udpHandler := dns.NewServeMux()
	udpHandler.HandleFunc(".", handler.UDP)

	tcpServer := &dns.Server{
		Addr:         s.host,
		Net:          "tcp",
		Handler:      tcpHandler,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
		ReusePort:    true,
	}

	udpServer := &dns.Server{
		Addr:         s.host,
		Net:          "udp",
		Handler:      udpHandler,
		UDPSize:      dns.DefaultMsgSize,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
		ReusePort:    true,
	}

	go s.start(udpServer)
	go s.start(tcpServer)

	if s.tlsHost != "" {
		cert, err := tls.LoadX509KeyPair(s.tlsCertificate, s.tlsPrivateKey)
		if err != nil {
			log.Crit("TLS certificate load failed", "error", err.Error())
			return
		}

		tlsServer := &dns.Server{
			Addr:         s.tlsHost,
			Net:          "tcp-tls",
			TLSConfig:    &tls.Config{Certificates: []tls.Certificate{cert}},
			Handler:      tcpHandler,
			ReadTimeout:  s.rTimeout,
			WriteTimeout: s.wTimeout,
		}

		go s.start(tlsServer)
	}

	if s.dohHost != "" {
		srv := &http.Server{
			Addr:         s.dohHost,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  30 * time.Second,
		}

		go func() {
			log.Info("DNS server listening...", "net", "https", "addr", s.dohHost)

			if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil {
				log.Crit("DNS listener failed", "net", "https", "addr", s.dohHost, "error", err.Error())
			}
		}()
	}
}

func (s *Server) start(ds *dns.Server) {
	log.Info("DNS server listening...", "net", ds.Net, "addr", ds.Addr)

	if err := ds.ListenAndServe(); err != nil {
		log.Crit("DNS listener failed", "net", ds.Net, "addr", ds.Addr, "error", err.Error())
	}
}
