package failover

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsclient"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

var (
	// failoverAttempts counts every time WriteMsg was about to write
	// a SERVFAIL and instead started trying fallback servers. One
	// increment per primary failure (not per fallback server tried).
	failoverAttempts = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_failover_attempts_total",
		Help: "Total times failover engaged after a SERVFAIL from primary resolution",
	})

	// failoverSuccess counts attempts that ended with a usable
	// answer from a fallback server. The ratio failoverSuccess /
	// failoverAttempts is the fallback-pool health signal.
	failoverSuccess = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_failover_success_total",
		Help: "Total queries answered by a fallback server after primary SERVFAIL",
	})
)

// Failover type.
type Failover struct {
	servers []string
}

// ResponseWriter implement of ctx.ResponseWriter.
type ResponseWriter struct {
	middleware.ResponseWriter

	f   *Failover
	ctx context.Context //nolint:containedctx // response writer is request-scoped and used synchronously
	req *dns.Msg
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

	ch.Writer = &ResponseWriter{ResponseWriter: w, f: f, ctx: ctx, req: ch.Request}
	// Restore via defer so a panicked downstream handler,
	// recovered higher up, still unwraps the chain before it
	// returns to the pool.
	defer func() { ch.Writer = w }()

	ch.Next(ctx)
}

// (*ResponseWriter).WriteMsg writeMsg implements the ctx.ResponseWriter interface.
func (w *ResponseWriter) WriteMsg(m *dns.Msg) error {
	if len(m.Question) == 0 || len(w.f.servers) == 0 {
		return w.ResponseWriter.WriteMsg(m)
	}

	if m.Rcode != dns.RcodeServerFailure || !m.RecursionDesired {
		return w.ResponseWriter.WriteMsg(m)
	}
	if middleware.RecursionWorkEnforcementError(w.ctx) != nil {
		return w.writeRecursionWorkFailure(m)
	}

	failoverAttempts.Inc()

	req := new(dns.Msg)
	req.SetQuestion(m.Question[0].Name, m.Question[0].Qtype)
	req.Question[0].Qclass = m.Question[0].Qclass
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	req.CheckingDisabled = m.CheckingDisabled

	var beforeAttempt func(string) error
	if middleware.RecursionWorkFrom(w.ctx) != nil {
		beforeAttempt = func(string) error {
			return middleware.DebitRecursionWork(w.ctx, middleware.RecursionWorkOutboundQuery)
		}
	}

	client := dnsclient.Client{
		Proto:         "udp",
		BeforeAttempt: beforeAttempt,
	}
	for _, server := range w.f.servers {
		// Preserve the historical independent five-second failover window.
		// Work accounting still reads the request-scoped ledger from w.ctx.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, _, err := client.Exchange(ctx, req, server)
		cancel()
		if err != nil {
			if errors.Is(err, middleware.ErrRecursionWorkLimit) {
				return w.writeRecursionWorkFailure(m)
			}
			zlog.Info("Failover query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
			continue
		}

		resp.Id = m.Id

		failoverSuccess.Inc()
		return w.ResponseWriter.WriteMsg(resp)
	}

	return w.ResponseWriter.WriteMsg(m)
}

func (w *ResponseWriter) writeRecursionWorkFailure(fallback *dns.Msg) error {
	req := w.req
	if req == nil {
		req = fallback
	}
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return w.ResponseWriter.WriteMsg(dnsutil.SetRcodeWithEDE(
		req,
		dns.RcodeServerFailure,
		do,
		middleware.RecursionWorkEDECode,
		middleware.RecursionWorkEDEText,
	))
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

const name = "failover"
