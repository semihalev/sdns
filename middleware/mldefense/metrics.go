package mldefense

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// MLDefenseQueriesTotal tracks total queries analyzed by ML defense
	MLDefenseQueriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mldefense_queries_total",
		Help: "Total number of DNS queries analyzed by ML defense",
	})

	// MLDefenseBlockedTotal tracks total queries blocked by ML defense
	MLDefenseBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mldefense_blocked_total",
		Help: "Total number of DNS queries blocked by ML defense",
	}, []string{"reason"})

	// MLDefenseSuspiciousTotal tracks suspicious but not blocked queries
	MLDefenseSuspiciousTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mldefense_suspicious_total",
		Help: "Total number of suspicious queries detected but not blocked",
	})

	// MLDefenseScoreHistogram tracks the distribution of anomaly scores
	MLDefenseScoreHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mldefense_score_distribution",
		Help:    "Distribution of anomaly scores for analyzed queries",
		Buckets: prometheus.LinearBuckets(0, 10, 11), // 0-100 in steps of 10
	})

	// MLDefenseAmplificationFactorHistogram tracks amplification factors
	MLDefenseAmplificationFactorHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mldefense_amplification_factor",
		Help:    "Distribution of DNS amplification factors",
		Buckets: []float64{1, 5, 10, 20, 50, 100, 200},
	})

	// MLDefenseIPProfilesActive tracks number of active IP profiles
	MLDefenseIPProfilesActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mldefense_ip_profiles_active",
		Help: "Number of active IP profiles being tracked",
	})

	// MLDefenseQueryTypeCounter tracks queries by type
	MLDefenseQueryTypeCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mldefense_query_type_total",
		Help: "Total number of queries by type analyzed by ML defense",
	}, []string{"qtype", "risk_level"})

	// MLDefenseBlockRate tracks the block rate as a gauge
	MLDefenseBlockRate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mldefense_block_rate_percent",
		Help: "Current block rate as a percentage",
	})
)
