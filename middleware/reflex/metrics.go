package reflex

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/semihalev/sdns/internal/metric"
)

var (
	// ReflexDetections counts suspected amplification attack sources.
	// Single-label CounterVec — alloc-free hot path via internal/metric.
	ReflexDetections = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "reflex_detections_total",
		Help: "Total suspected amplification attack detections by query type",
	}, []string{"qtype"})

	// ReflexBlocked counts blocked queries.
	ReflexBlocked = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "reflex_blocked_total",
		Help: "Total queries blocked due to amplification attack suspicion",
	})

	// ReflexTrackedIPs shows current tracked IP count — Gauge stays on
	// direct Prometheus (internal/metric is scalar-counter only).
	ReflexTrackedIPs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "reflex_tracked_ips",
		Help: "Number of IPs currently being tracked",
	})
)
