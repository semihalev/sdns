package hostsfile

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

// Mirror of the in-memory db.stats counters so operators can read
// hostsfile hit/lookup rates from Prometheus without polling the
// admin Stats() endpoint. Both increments happen — the internal
// counter is still used by Stats() callers; the metric counter is
// for scrape.
var (
	hostsfileLookups = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_hostsfile_lookups_total",
		Help: "Total lookups attempted against the hosts file",
	})
	hostsfileHits = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_hostsfile_hits_total",
		Help: "Total lookups that matched a hosts file entry",
	})
)
