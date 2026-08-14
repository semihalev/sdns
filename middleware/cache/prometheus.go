package cache

import (
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
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

	failureCacheHits = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "failure_cache_hits_total",
		Help: "Total number of RFC 9520 cached resolution failures served",
	})

	wireFastPath = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_cache_wire_fastpath_total",
		Help: "Cache hits attempted on the byte serving path, by outcome",
	}, []string{"outcome"})

	wireFastServed   = wireFastPath.Register("served")
	wireFastFallback = wireFastPath.Register("fallback")

	// A hit that never attempts the byte path is counted by what stopped it.
	// Serving bytes is what keeps a hit from decoding and re-encoding a
	// message it already holds, so which gate turns hits away decides where
	// widening it would pay.
	wireSkipInternal = wireFastPath.Register("skip_internal")
	wireSkipEntry    = wireFastPath.Register("skip_entry")
	wireSkipWriter   = wireFastPath.Register("skip_writer")
	wireSkipDNSSEC   = wireFastPath.Register("skip_dnssec")
	wireSkipSize     = wireFastPath.Register("skip_size")
	wireSkipBuild    = wireFastPath.Register("skip_build")
	wireSkipChase    = wireFastPath.Register("skip_chase")
	wireChaseServed  = wireFastPath.Register("chase_served")

	nxDomainCutHits = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "nxdomain_cut_hits_total",
		Help: "Total number of descendant NXDOMAIN responses served from locally validated RFC 8020 cuts",
	})

	aggressiveNegativeHits = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "aggressive_negative_hits_total",
		Help: "RFC 8198 negative responses synthesized from locally validated denial proofs",
	}, []string{"proof", "rcode"})

	// Closed label set: pre-resolve the four supported combinations so the
	// request hot path avoids a label-map lookup and cannot create unbounded
	// series from wire values.
	aggressiveNSECNXDomainHits  = aggressiveNegativeHits.Register("nsec", "nxdomain")
	aggressiveNSECNODATAHits    = aggressiveNegativeHits.Register("nsec", "nodata")
	aggressiveNSEC3NXDomainHits = aggressiveNegativeHits.Register("nsec3", "nxdomain")
	aggressiveNSEC3NODATAHits   = aggressiveNegativeHits.Register("nsec3", "nodata")

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
	failureCacheLen  func() int
	nxDomainCutLen   func() int
	denialProofLen   func() int
)

func init() {
	prometheus.MustRegister(cacheSize)
	prometheus.MustRegister(cacheHitRate)
}

// SetMetricsInstance sets the metrics instance for hit rate calculation
func SetMetricsInstance(m *CacheMetrics) {
	metricsInstance = m
}

// SetCacheSizeFuncs sets the functions to get cache sizes. Optional functions
// preserve the original two-argument source contract: extras[0] is the RFC
// 9520 failure cache, extras[1] the RFC 8020 cut index, and extras[2] the RFC
// 8198 proof index.
func SetCacheSizeFuncs(positive, negative func() int, extras ...func() int) {
	positiveCacheLen = positive
	negativeCacheLen = negative
	failureCacheLen = nil
	nxDomainCutLen = nil
	denialProofLen = nil
	if len(extras) > 0 {
		failureCacheLen = extras[0]
	}
	if len(extras) > 1 {
		nxDomainCutLen = extras[1]
	}
	if len(extras) > 2 {
		denialProofLen = extras[2]
	}
}

// UpdateCacheSizeMetrics updates the cache size gauges
func UpdateCacheSizeMetrics() {
	if positiveCacheLen != nil {
		cacheSize.WithLabelValues("positive").Set(float64(positiveCacheLen()))
	}
	if negativeCacheLen != nil {
		cacheSize.WithLabelValues("negative").Set(float64(negativeCacheLen()))
	}
	if failureCacheLen != nil {
		cacheSize.WithLabelValues("failure").Set(float64(failureCacheLen()))
	}
	if nxDomainCutLen != nil {
		cacheSize.WithLabelValues("nxdomain_cut").Set(float64(nxDomainCutLen()))
	}
	if denialProofLen != nil {
		cacheSize.WithLabelValues("denial_proof").Set(float64(denialProofLen()))
	}
}

func observeAggressiveNegativeHit(kind middleware.ValidatedNegativeProofKind, rcode int) {
	switch {
	case kind == middleware.ValidatedNegativeProofNSEC && rcode == dns.RcodeNameError:
		aggressiveNSECNXDomainHits.Inc()
	case kind == middleware.ValidatedNegativeProofNSEC && rcode == dns.RcodeSuccess:
		aggressiveNSECNODATAHits.Inc()
	case kind == middleware.ValidatedNegativeProofNSEC3 && rcode == dns.RcodeNameError:
		aggressiveNSEC3NXDomainHits.Inc()
	case kind == middleware.ValidatedNegativeProofNSEC3 && rcode == dns.RcodeSuccess:
		aggressiveNSEC3NODATAHits.Inc()
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
