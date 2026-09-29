package resolver

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/metric"
)

// The resolver's own caches, delegations and nameserver glue, keep an
// entry until it is replaced or evicted: a read that finds one expired
// reports it and leaves it where it is. Under traffic that keeps touching
// new zones, those fill to capacity with entries nothing will read again.
// The pruner removes them through each cache's expiry index, which files
// every entry for the instant it runs out, and publishes the caches'
// sizes, which nothing else reports.
const resolverPruneInterval = 30 * time.Second

var (
	resolverCacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_resolver_cache_size",
		Help: "Entries the resolver's caches hold, expired ones not yet pruned included",
	}, []string{"type"})

	resolverCachePruned = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_resolver_cache_pruned_total",
		Help: "Expired entries the pruner removed from the resolver's caches",
	}, []string{"type"})

	prunedDelegations = resolverCachePruned.Register("delegation")
	prunedGlueV4      = resolverCachePruned.Register("glue_v4")
	prunedGlueV6      = resolverCachePruned.Register("glue_v6")
)

func (r *Resolver) pruneLoop() {
	ticker := time.NewTicker(resolverPruneInterval)
	defer ticker.Stop()
	for now := range ticker.C {
		r.pruneCaches(now)
	}
}

// pruneCaches removes the delegations and the glue whose time is up at now
// and whose expiry records have come due, and publishes what is left.
func (r *Resolver) pruneCaches(now time.Time) {
	prunedDelegations.Add(int64(r.delegations.Prune()))
	resolverCacheSize.WithLabelValues("delegation").Set(float64(r.delegations.Len()))

	// The same wall-clock horizon glueGet reads glue by.
	judgeGlue := func(e *glueEntry) (cache.Verdict, time.Duration) {
		left := time.Duration(e.expiresAt - now.UnixNano())
		if left <= 0 {
			return cache.Dead, 0
		}
		return cache.Alive, left
	}
	prunedGlueV4.Add(int64(r.glueV4.Expire(judgeGlue)))
	resolverCacheSize.WithLabelValues("glue_v4").Set(float64(r.glueV4.Len()))
	if r.glueV6 != nil {
		prunedGlueV6.Add(int64(r.glueV6.Expire(judgeGlue)))
		resolverCacheSize.WithLabelValues("glue_v6").Set(float64(r.glueV6.Len()))
	}
}
