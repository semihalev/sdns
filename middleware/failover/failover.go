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
	"github.com/semihalev/sdns/internal/contextutil"
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
	seen := make(map[string]struct{})
	for _, s := range cfg.FallbackServers {
		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			key := middleware.CanonicalResolutionEndpoint(s)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			fallbackservers = append(fallbackservers, s)
		} else if ip != nil && ip.To16() != nil {
			key := middleware.CanonicalResolutionEndpoint(s)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
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
	ctx, _ = middleware.EnsureResolutionAttemptGuard(ctx)

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
		return w.writeRecursionWorkFailure(m, nil)
	}

	requestLocalErr := middleware.RequestLocalFailureForResponse(w.ctx, m)
	if requestErr := contextutil.EffectiveError(w.ctx); requestErr != nil {
		middleware.MarkRequestLocalFailureResponse(w.ctx, m, requestErr)
		return w.ResponseWriter.WriteMsg(m)
	}
	// This response is the cache probe's deliberate cohort shed. Starting a
	// fallback query here would bypass the very work bound it enforces.
	if errors.Is(requestLocalErr, middleware.ErrFailureProbeLimit) {
		return w.ResponseWriter.WriteMsg(m)
	}

	failoverAttempts.Inc()

	req := new(dns.Msg)
	req.SetQuestion(m.Question[0].Name, m.Question[0].Qtype)
	req.Question[0].Qclass = m.Question[0].Qclass
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	req.CheckingDisabled = m.CheckingDisabled

	var failureResponse *dns.Msg
	for _, server := range w.f.servers {
		if requestErr := contextutil.EffectiveError(w.ctx); requestErr != nil {
			middleware.MarkRequestLocalFailureResponse(w.ctx, m, requestErr)
			return w.ResponseWriter.WriteMsg(m)
		}
		client := dnsclient.Client{
			Proto: "udp",
			BeforeAttempt: func(proto string) error {
				if err := middleware.BeginResolutionAttempt(w.ctx, req.Question[0], server, proto); err != nil {
					return err
				}
				return middleware.DebitRecursionWork(w.ctx, middleware.RecursionWorkOutboundQuery)
			},
		}
		// Keep the historical five-second per-endpoint ceiling, but derive it
		// from the pipeline-ingress request so querytimeout and transport
		// cancellation remain hard resolution bounds.
		attemptCtx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
		resp, _, err := client.Exchange(attemptCtx, req, server)
		cancel()
		if err != nil {
			if requestErr := contextutil.EffectiveError(w.ctx); requestErr != nil {
				middleware.MarkRequestLocalFailureResponse(w.ctx, m, requestErr)
				return w.ResponseWriter.WriteMsg(m)
			}
			// A child five-second deadline with a still-live request is shared
			// upstream failure evidence; only an explicit request-tree attempt
			// rejection carries local provenance here.
			if errors.Is(err, middleware.ErrResolutionAttemptLimit) {
				// Request-local retry exhaustion is not an upstream health
				// failure; try another endpoint without noisy logging.
				if requestLocalErr == nil {
					requestLocalErr = err
				}
				continue
			}
			if errors.Is(err, middleware.ErrRecursionWorkLimit) {
				return w.writeRecursionWorkFailure(m, err)
			}
			zlog.Info("Failover query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
			continue
		}

		resp.Id = m.Id
		// The fallback is answering the original client request. Do not trust
		// an upstream to echo CD correctly: cache failure isolation and
		// success reset both key on this bit.
		resp.CheckingDisabled = m.CheckingDisabled
		responseType, _ := dnsutil.ClassifyResponse(resp, time.Now())
		if responseType == dnsutil.TypeServerFailure {
			if failureResponse == nil {
				failureResponse = resp
			}
			continue
		}

		failoverSuccess.Inc()
		return w.ResponseWriter.WriteMsg(resp)
	}

	if failureResponse != nil {
		if requestLocalErr != nil {
			middleware.MarkRequestLocalFailureResponse(w.ctx, failureResponse, requestLocalErr)
		}
		return w.ResponseWriter.WriteMsg(failureResponse)
	}
	if requestLocalErr != nil {
		middleware.MarkRequestLocalFailureResponse(w.ctx, m, requestLocalErr)
	}
	return w.ResponseWriter.WriteMsg(m)
}

func (w *ResponseWriter) writeRecursionWorkFailure(fallback *dns.Msg, workErr error) error {
	req := w.req
	if req == nil {
		req = fallback
	}
	edeCode, edeText := middleware.RecursionWorkErrorEDE(w.ctx, workErr)
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return w.ResponseWriter.WriteMsg(dnsutil.SetRcodeWithEDE(
		req,
		dns.RcodeServerFailure,
		do,
		edeCode,
		edeText,
	))
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

const name = "failover"
