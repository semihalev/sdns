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
	"github.com/semihalev/sdns/middleware"
)

// Metrics type
type Metrics struct {
	queries *prometheus.CounterVec

	// Domain metrics with concurrent access tracking
	domainMetricsEnabled bool
	domainMetricsLimit   int // Max domains to track (memory limit)
	domainQueries        *prometheus.CounterVec
	domainTracker        sync.Map // Concurrent map of tracked domains
	domainCount          int32    // Atomic counter for domain count
	domainCleanupMu      sync.Mutex
	lastCleanup          time.Time
}

// New return new metrics
func New(cfg *config.Config) *Metrics {
	m := &Metrics{
		queries: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dns_queries_total",
				Help: "How many DNS queries processed",
			},
			[]string{"qtype", "rcode"},
		),
		domainMetricsEnabled: cfg.DomainMetrics,
		domainMetricsLimit:   cfg.DomainMetricsLimit,
	}
	_ = prometheus.Register(m.queries)

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

// Name return middleware name
func (m *Metrics) Name() string { return name }

// ServeDNS implements the Handle interface.
func (m *Metrics) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	ch.Next(ctx)

	if !ch.Writer.Written() {
		return
	}

	question := ch.Request.Question[0]

	// Update general metrics
	labels := AcquireLabels()
	defer ReleaseLabels(labels)

	labels["qtype"] = dns.TypeToString[question.Qtype]
	labels["rcode"] = dns.RcodeToString[ch.Writer.Rcode()]

	m.queries.With(labels).Inc()

	// Update domain metrics if enabled
	if m.domainMetricsEnabled {
		m.recordDomainQuery(question.Name)
	}
}

// recordDomainQuery records a query for a specific domain
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

// maybeCleanupDomains removes domains with lowest query counts if needed
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

	m.domainTracker.Range(func(key, _ interface{}) bool {
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

var labelsPool sync.Pool

// AcquireLabels returns a label from pool
func AcquireLabels() prometheus.Labels {
	x := labelsPool.Get()
	if x == nil {
		return prometheus.Labels{"qtype": "", "rcode": ""}
	}

	return x.(prometheus.Labels)
}

// ReleaseLabels returns labels to pool
func ReleaseLabels(labels prometheus.Labels) {
	labelsPool.Put(labels)
}

const name = "metrics"
