package cache

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

// Counters use the internal/metric package (sharded + background
// flush) — they're on the per-query hot path and benefit ~20x from
// avoiding the direct prometheus.Counter atomic.
//
// Gauges (cacheSize, cacheHitRate) stay on direct Prometheus —
// internal/metric is scalar-counter only, and these are scraped
// once per Prometheus pull, not on every request.
var (
	cacheHits = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_cache_hits_total",
		Help: "Total number of DNS cache hits",
	})

	cacheMisses = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_cache_misses_total",
		Help: "Total number of DNS cache misses",
	})

	cacheEvictions = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_cache_evictions_total",
		Help: "Total number of DNS cache evictions",
	})

	cachePrefetches = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_cache_prefetches_total",
		Help: "Total number of DNS cache prefetches",
	})

	cacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_cache_size",
		Help: "Current number of entries in the DNS cache",
	}, []string{"type"})

	// cacheHitRate is calculated as hits / (hits + misses) * 100
	cacheHitRate = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "dns_cache_hit_rate",
		Help: "DNS cache hit rate percentage",
	}, calculateHitRate)

	// ECS-specific counter (RFC 7871). Counts only requests that
	// went through the ECS-aware lookup path; non-ECS lookups are
	// already counted by dns_cache_hits_total /
	// dns_cache_misses_total and aren't duplicated here. outcome
	// labels:
	//   - hit_scoped: scoped lookup found the entry
	//   - hit_shared: scoped lookup missed, shared-key hit (SCOPE=0
	//                 authority answer or pre-Stage-2 entry)
	//   - miss:       both scoped probe and shared-key check missed
	ecsLookups = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_cache_ecs_lookups_total",
		Help: "ECS-aware cache lookups, partitioned by outcome",
	}, []string{"outcome"})

	// Pre-resolved ECS outcome handles to skip the per-call map
	// lookup. Closed set: any new outcome must be added here too.
	ecsLookupHitScoped = ecsLookups.Register("hit_scoped")
	ecsLookupHitShared = ecsLookups.Register("hit_shared")
	ecsLookupMiss      = ecsLookups.Register("miss")
)

// cacheInstance holds references to cache components for metrics
var (
	metricsInstance  *CacheMetrics
	positiveCacheLen func() int
	negativeCacheLen func() int
)

func init() {
	prometheus.MustRegister(cacheSize)
	prometheus.MustRegister(cacheHitRate)
}

// SetMetricsInstance sets the metrics instance for hit rate calculation
func SetMetricsInstance(m *CacheMetrics) {
	metricsInstance = m
}

// SetCacheSizeFuncs sets the functions to get cache sizes
func SetCacheSizeFuncs(positive, negative func() int) {
	positiveCacheLen = positive
	negativeCacheLen = negative
}

// UpdateCacheSizeMetrics updates the cache size gauges
func UpdateCacheSizeMetrics() {
	if positiveCacheLen != nil {
		cacheSize.WithLabelValues("positive").Set(float64(positiveCacheLen()))
	}
	if negativeCacheLen != nil {
		cacheSize.WithLabelValues("negative").Set(float64(negativeCacheLen()))
	}
}

func calculateHitRate() float64 {
	// Update cache size metrics while calculating hit rate
	UpdateCacheSizeMetrics()

	if metricsInstance == nil {
		return 0
	}
	hits, misses, _, _ := metricsInstance.Stats()
	total := float64(hits + misses)
	if total == 0 {
		return 0
	}
	return float64(hits) / total * 100
}
