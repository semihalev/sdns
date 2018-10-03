package main

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

// Server type
type Server struct {
	host     string
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

	tcpServer := &dns.Server{Addr: s.host,
		Net:          "tcp",
		Handler:      tcpHandler,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
		ReusePort:    true,
	}

	udpServer := &dns.Server{Addr: s.host,
		Net:          "udp",
		Handler:      udpHandler,
		UDPSize:      dns.DefaultMsgSize,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout,
		ReusePort:    true,
	}

	go s.start(udpServer)
	go s.start(tcpServer)
}

func (s *Server) start(ds *dns.Server) {
	log.Info("DNS server listening...", "net", ds.Net, "addr", s.host)

	if err := ds.ListenAndServe(); err != nil {
		log.Crit("DNS listener failed", "net", ds.Net, "addr", s.host, "error", err.Error())
	}
}
