package metrics

import (
	"context"
	"sync"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/middleware"
)

// Metrics type
type Metrics struct {
	queries *prometheus.CounterVec
}

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
		return New(cfg)
	})
}

// New return new metrics
func New(cfg *config.Config) *Metrics {
	m := &Metrics{
		queries: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dns_queries_total",
				Help: "How many DNS queries processed",
			},
			[]string{"qtype", "rcode"},
		),
	}
	prometheus.Register(m.queries)

	return m
}

// Name return middleware name
func (m *Metrics) Name() string { return name }

// ServeDNS implements the Handle interface.
func (m *Metrics) ServeDNS(ctx context.Context, dc *ctx.Context) {
	dc.NextDNS(ctx)

	if !dc.DNSWriter.Written() {
		return
	}

	labels := AcquireLabels()
	defer ReleaseLabels(labels)

	labels["qtype"] = dns.TypeToString[dc.DNSRequest.Question[0].Qtype]
	labels["rcode"] = dns.RcodeToString[dc.DNSWriter.Rcode()]

	m.queries.With(labels).Inc()
}

var labelsPool sync.Pool

// AcquireLabels returns a label from pool
func AcquireLabels() prometheus.Labels {
	x := labelsPool.Get()
	if x == nil {
		return prometheus.Labels{"qtype": "", "rcode": ""}
	}

	return x.(prometheus.Labels)
}

// ReleaseLabels returns labels to pool
func ReleaseLabels(labels prometheus.Labels) {
	labelsPool.Put(labels)
}

const name = "metrics"
