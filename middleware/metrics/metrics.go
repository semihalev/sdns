package metrics

import (
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
)

// Metrics type
type Metrics struct {
	queries *prometheus.CounterVec
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
func (m *Metrics) Name() string {
	return "metrics"
}

// ServeDNS implements the Handle interface.
func (m *Metrics) ServeDNS(dc *ctx.Context) {
	dc.NextDNS()

	if !dc.DNSWriter.Written() {
		return
	}

	m.queries.With(
		prometheus.Labels{
			"qtype": dns.TypeToString[dc.DNSRequest.Question[0].Qtype],
			"rcode": dns.RcodeToString[dc.DNSWriter.Rcode()],
		}).Inc()
}
