package chaos

import (
	"context"
	"os"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// Chaos type
type Chaos struct {
	chaos   bool
	version string
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return accesslist
func New(cfg *config.Config) *Chaos {
	return &Chaos{
		version: "SDNS v" + cfg.ServerVersion() + " (github.com/semihalev/sdns)",
		chaos:   cfg.Chaos,
	}
}

// Name return middleware name
func (c *Chaos) Name() string { return name }

// ServeDNS implements the Handle interface.
func (c *Chaos) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	q := req.Question[0]

	if q.Qclass != dns.ClassCHAOS || q.Qtype != dns.TypeTXT || !c.chaos {
		ch.Next(ctx)
		return
	}

	resp := new(dns.Msg)
	resp.SetReply(req)

	switch q.Name {
	case "version.bind.", "version.server.":
		resp.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  q.Qclass,
				},
				Txt: []string{c.version},
			}}
	case "hostname.bind.", "id.server.":
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		resp.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  q.Qclass,
				},
				Txt: []string{limitTXTLength(hostname)},
			}}
	default:
		ch.Next(ctx)
		return
	}

	_ = w.WriteMsg(resp)
	ch.Cancel()
}

func limitTXTLength(s string) string {
	if len(s) < 256 {
		return s
	}
	return s[:255]
}

const name = "chaos"
