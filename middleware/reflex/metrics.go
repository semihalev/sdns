package reflex

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ReflexDetections counts suspected amplification attack sources.
	ReflexDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "reflex_detections_total",
			Help: "Total suspected amplification attack detections by query type",
		},
		[]string{"qtype"},
	)

	// ReflexBlocked counts blocked queries.
	ReflexBlocked = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "reflex_blocked_total",
			Help: "Total queries blocked due to amplification attack suspicion",
		},
	)

	// ReflexTrackedIPs shows current tracked IP count.
	ReflexTrackedIPs = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "reflex_tracked_ips",
			Help: "Number of IPs currently being tracked",
		},
	)
)
