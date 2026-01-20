package failover

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
)

// Failover type.
type Failover struct {
	servers []string
}

// ResponseWriter implement of ctx.ResponseWriter.
type ResponseWriter struct {
	middleware.ResponseWriter

	f *Failover
}

// New return failover.
func New(cfg *config.Config) *Failover {
	fallbackservers := []string{}
	for _, s := range cfg.FallbackServers {
		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			fallbackservers = append(fallbackservers, s)
		} else if ip != nil && ip.To16() != nil {
			fallbackservers = append(fallbackservers, s)
		} else {
			zlog.Error("Fallback server is not correct. Check your config.", "server", s)
		}
	}

	return &Failover{servers: fallbackservers}
}

// (*Failover).Name name return middleware name.
func (f *Failover) Name() string { return name }

// (*Failover).ServeDNS serveDNS implements the Handle interface.
func (f *Failover) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w := ch.Writer

	ch.Writer = &ResponseWriter{ResponseWriter: w, f: f}

	ch.Next(ctx)

	ch.Writer = w
}

// (*ResponseWriter).WriteMsg writeMsg implements the ctx.ResponseWriter interface.
func (w *ResponseWriter) WriteMsg(m *dns.Msg) error {
	if len(m.Question) == 0 || len(w.f.servers) == 0 {
		return w.ResponseWriter.WriteMsg(m)
	}

	if m.Rcode != dns.RcodeServerFailure || !m.RecursionDesired {
		return w.ResponseWriter.WriteMsg(m)
	}

	req := new(dns.Msg)
	req.SetQuestion(m.Question[0].Name, m.Question[0].Qtype)
	req.Question[0].Qclass = m.Question[0].Qclass
	req.SetEdns0(util.DefaultMsgSize, true)
	req.CheckingDisabled = m.CheckingDisabled

	ctx := context.Background()

	for _, server := range w.f.servers {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		resp, err := util.Exchange(ctx, req, server, "udp", nil)
		if err != nil {
			zlog.Info("Failover query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
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
