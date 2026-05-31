package kubernetes

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

// Prometheus exports for the existing internal counters. Dual-write
// here keeps the existing Stats() / debug paths working unchanged
// while giving operators a scrape-able view of pod-discovery health.
var (
	kubernetesQueries = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_kubernetes_queries_total",
		Help: "Total queries served by the kubernetes middleware",
	})
	kubernetesAnswered = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_kubernetes_answered_total",
		Help: "Total queries the kubernetes middleware answered authoritatively",
	})
	kubernetesErrors = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_kubernetes_errors_total",
		Help: "Total kubernetes lookup or response-build errors",
	})
	kubernetesWriteErrors = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_kubernetes_write_errors_total",
		Help: "Total writes to the client that failed (subset of dns_kubernetes_errors_total)",
	})
)
