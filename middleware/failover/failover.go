package failover

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// Failover type
type Failover struct {
	servers []string
}

// ResponseWriter implement of ctx.ResponseWriter
type ResponseWriter struct {
	middleware.ResponseWriter

	f *Failover
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return failover
func New(cfg *config.Config) *Failover {
	fallbackservers := []string{}
	for _, s := range cfg.FallbackServers {
		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			fallbackservers = append(fallbackservers, s)
		} else if ip != nil && ip.To16() != nil {
			fallbackservers = append(fallbackservers, s)
		} else {
			log.Error("Fallback server is not correct. Check your config.", "server", s)
		}
	}

	return &Failover{servers: fallbackservers}
}

// Name return middleware name
func (f *Failover) Name() string { return name }

// ServeDNS implements the Handle interface.
func (f *Failover) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w := ch.Writer

	ch.Writer = &ResponseWriter{ResponseWriter: w, f: f}

	ch.Next(ctx)

	ch.Writer = w
}

// WriteMsg implements the ctx.ResponseWriter interface
func (w *ResponseWriter) WriteMsg(m *dns.Msg) error {
	if len(m.Question) == 0 || len(w.f.servers) == 0 {
		return w.ResponseWriter.WriteMsg(m)
	}

	if m.Rcode != dns.RcodeServerFailure || !m.RecursionDesired {
		return w.ResponseWriter.WriteMsg(m)
	}

	req := new(dns.Msg)
	req.SetQuestion(m.Question[0].Name, m.Question[0].Qtype)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	req.RecursionDesired = true
	req.CheckingDisabled = m.CheckingDisabled

	for _, server := range w.f.servers {
		resp, err := dns.Exchange(req, server)
		if err != nil {
			log.Warn("Failover query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
			continue
		}

		resp.Id = m.Id

		return w.ResponseWriter.WriteMsg(resp)
	}

	return w.ResponseWriter.WriteMsg(m)
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

const name = "failover"
