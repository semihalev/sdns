package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	l "log"

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
			Addr:         s.dohHost,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  30 * time.Second,
			ErrorLog:     l.New(logWriter, "", 0),
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
