package forwarder

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
)

type server struct {
	Addr  string
	Proto string
}

// Forwarder type.
type Forwarder struct {
	servers []*server
	dnssec  bool
}

// New return forwarder.
func New(cfg *config.Config) *Forwarder {
	forwarderservers := []*server{}
	for _, s := range cfg.ForwarderServers {
		srv := &server{Proto: "udp"}

		if strings.HasPrefix(s, "tls://") {
			s = strings.TrimPrefix(s, "tls://")
			srv.Proto = "tcp-tls"
		}

		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			srv.Addr = s
			forwarderservers = append(forwarderservers, srv)
		} else if ip != nil && ip.To16() != nil {
			srv.Addr = s
			forwarderservers = append(forwarderservers, srv)
		} else {
			zlog.Error("Forwarder server is not correct. Check your config.", "server", s)
		}
	}

	return &Forwarder{servers: forwarderservers, dnssec: cfg.DNSSEC == "on"}
}

// (*Forwarder).Name name return middleware name.
func (f *Forwarder) Name() string { return name }

// (*Forwarder).ServeDNS serveDNS implements the Handle interface.
func (f *Forwarder) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if len(req.Question) == 0 || len(f.servers) == 0 {
		ch.CancelWithRcode(dns.RcodeServerFailure, true)
		return
	}

	if !req.CheckingDisabled {
		req.CheckingDisabled = !f.dnssec
	}

	for _, server := range f.servers {
		resp, err := util.Exchange(ctx, req, server.Addr, server.Proto)
		if err != nil {
			zlog.Info("forwarder query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
			continue
		}

		resp.Id = req.Id
		if !f.dnssec {
			resp.CheckingDisabled = false
		}

		_ = w.WriteMsg(resp)
		return
	}

	ch.CancelWithRcode(dns.RcodeServerFailure, true)
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

const name = "forwarder"
