package metrics

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
)

// queries is the multi-label per-query counter. Closed cardinality
// (qtypes ~30, rcodes ~24) so internal/metric is a fit; the hot path
// is ~12 ns/op vs ~120 ns/op for the prior With(pooled-labels) call.
//
// Package-level rather than per-Metrics-instance because:
//   - prometheus.MustRegister panics on duplicates, so re-creation
//     wouldn't work anyway
//   - metric.NewCounterVec auto-starts the flusher; doing it once
//     at init keeps lifecycle simple
//   - middleware.Setup wires exactly one instance in production
var queries = metric.NewCounterVec(nil, prometheus.CounterOpts{
	Name: "dns_queries_total",
	Help: "How many DNS queries processed",
}, []string{"qtype", "rcode"})

// Metrics type.
type Metrics struct {
	// Domain metrics with concurrent access tracking. Stays on
	// direct prometheus.CounterVec because the label cardinality
	// (per-domain) is unbounded — internal/metric is for closed
	// label sets only.
	domainMetricsEnabled bool
	domainMetricsLimit   int // Max domains to track (memory limit)
	domainQueries        *prometheus.CounterVec
	domainTracker        sync.Map // Concurrent map of tracked domains
	domainCount          int32    // Atomic counter for domain count
	domainCleanupMu      sync.Mutex
	lastCleanup          time.Time
}

// New return new metrics.
func New(cfg *config.Config) *Metrics {
	m := &Metrics{
		domainMetricsEnabled: cfg.DomainMetrics,
		domainMetricsLimit:   cfg.DomainMetricsLimit,
	}

	// Initialize domain metrics if enabled
	if m.domainMetricsEnabled {
		m.domainQueries = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dns_domain_queries_total",
				Help: "How many DNS queries processed per domain",
			},
			[]string{"domain"},
		)
		_ = prometheus.Register(m.domainQueries)
	}

	return m
}

// (*Metrics).Name name return middleware name.
func (m *Metrics) Name() string { return name }

// (*Metrics).ClientOnly marks metrics as a client-traffic
// observer; the middleware.Setup sub-pipeline excludes it so
// internal sub-queries don't inflate per-query counters.
func (m *Metrics) ClientOnly() bool { return true }

// (*Metrics).ServeDNS serveDNS implements the Handle interface.
func (m *Metrics) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	ch.Next(ctx)

	if !ch.Writer.Written() {
		return
	}

	question := ch.Request.Question[0]

	// Hot path: single WithLabelValues lookup against the COW map,
	// per-CPU sharded atomic add. ~12 ns/op under 8-core contention.
	queries.WithLabelValues(
		dns.TypeToString[question.Qtype],
		dns.RcodeToString[ch.Writer.Rcode()],
	).Inc()

	// Update domain metrics if enabled
	if m.domainMetricsEnabled {
		m.recordDomainQuery(question.Name)
	}
}

// recordDomainQuery records a query for a specific domain.
func (m *Metrics) recordDomainQuery(qname string) {
	// Filter: skip TLDs and single-label domains
	if dns.CountLabel(qname) < 2 {
		return
	}

	// Normalize domain name (lowercase and remove trailing dot)
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))

	// Fast path: increment if already tracking
	if _, exists := m.domainTracker.Load(domain); exists {
		// Domain already tracked, just increment
		m.domainQueries.WithLabelValues(domain).Inc()
		return
	}

	// New domain - check if we're at limit
	if m.domainMetricsLimit > 0 {
		currentCount := atomic.LoadInt32(&m.domainCount)
		if int(currentCount) >= m.domainMetricsLimit {
			// At limit - check if we should run cleanup
			m.maybeCleanupDomains()

			// After cleanup, check count again
			currentCount = atomic.LoadInt32(&m.domainCount)
			if int(currentCount) >= m.domainMetricsLimit {
				// Still at limit after cleanup
				// Don't track this domain for now, it will be picked up
				// in the next cleanup cycle if it becomes popular
				return
			}
		}
	}

	// Add the new domain (atomic operation)
	if _, loaded := m.domainTracker.LoadOrStore(domain, true); !loaded {
		// Successfully added new domain
		atomic.AddInt32(&m.domainCount, 1)
		// Increment the counter for this domain
		m.domainQueries.WithLabelValues(domain).Inc()

		// Check if we need cleanup after adding
		if m.domainMetricsLimit > 0 {
			currentCount := atomic.LoadInt32(&m.domainCount)
			if int(currentCount) > m.domainMetricsLimit {
				m.maybeCleanupDomains()
			}
		}
	}
}

// maybeCleanupDomains removes domains with lowest query counts if needed.
func (m *Metrics) maybeCleanupDomains() {
	// Prevent concurrent cleanups
	if !m.domainCleanupMu.TryLock() {
		return
	}
	defer m.domainCleanupMu.Unlock()

	// Rate limit cleanups (5 min) unless over limit
	currentCount := atomic.LoadInt32(&m.domainCount)
	if int(currentCount) <= m.domainMetricsLimit && time.Since(m.lastCleanup) < 5*time.Minute {
		return
	}
	m.lastCleanup = time.Now()

	// Collect all domains and their counts
	type domainCount struct {
		domain string
		count  float64
	}
	var domains []domainCount

	m.domainTracker.Range(func(key, _ any) bool {
		domain := key.(string)
		// Get current count from Prometheus
		metric := &dto.Metric{}
		if m.domainQueries.WithLabelValues(domain).Write(metric) == nil {
			if metric.Counter != nil && metric.Counter.Value != nil {
				count := *metric.Counter.Value
				domains = append(domains, domainCount{domain: domain, count: count})
			}
		}
		return true
	})

	// If we're not over limit, no need to clean
	if len(domains) <= m.domainMetricsLimit {
		return
	}

	// Sort by count (descending) to keep top domains
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].count > domains[j].count
	})

	// Evict least queried domains to stay within limit
	for i := m.domainMetricsLimit; i < len(domains); i++ {
		domain := domains[i].domain
		m.domainTracker.Delete(domain)
		atomic.AddInt32(&m.domainCount, -1)
		// Remove from Prometheus
		m.domainQueries.DeleteLabelValues(domain)
	}
}

const name = "metrics"
