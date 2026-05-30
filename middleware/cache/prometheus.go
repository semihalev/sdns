package cache

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	cacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_hits_total",
		Help: "Total number of DNS cache hits",
	})

	cacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_misses_total",
		Help: "Total number of DNS cache misses",
	})

	cacheEvictions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_evictions_total",
		Help: "Total number of DNS cache evictions",
	})

	cachePrefetches = prometheus.NewCounter(prometheus.CounterOpts{
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

	// ECS-specific counters (RFC 7871). Tracks how much of the cache
	// traffic the ECS-aware path is handling vs the shared-key
	// fallback. outcome labels:
	//   - hit_scoped:     scoped lookup found the entry
	//   - hit_shared:     scoped lookup missed, shared-key hit (SCOPE=0 or pre-Stage-2 entry)
	//   - miss:           neither path found an entry
	//   - non_ecs:        request had no ECS or policy didn't apply; shared-key path only
	ecsLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_cache_ecs_lookups_total",
		Help: "ECS-aware cache lookups, partitioned by outcome",
	}, []string{"outcome"})
)

// cacheInstance holds references to cache components for metrics
var (
	metricsInstance  *CacheMetrics
	positiveCacheLen func() int
	negativeCacheLen func() int
)

func init() {
	prometheus.MustRegister(cacheHits)
	prometheus.MustRegister(cacheMisses)
	prometheus.MustRegister(cacheEvictions)
	prometheus.MustRegister(cachePrefetches)
	prometheus.MustRegister(cacheSize)
	prometheus.MustRegister(cacheHitRate)
	prometheus.MustRegister(ecsLookups)
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
