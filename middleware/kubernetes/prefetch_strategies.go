package kubernetes

import (
	"github.com/miekg/dns"
	"strings"
)

// PrefetchStrategy defines common prefetch patterns for Kubernetes services
type PrefetchStrategy struct {
	// Common service patterns that often query each other
	servicePatterns map[string][]string

	// Namespace-aware patterns
	namespacePatterns map[string][]string
}

// NewPrefetchStrategy creates a new prefetch strategy with common patterns
func NewPrefetchStrategy() *PrefetchStrategy {
	return &PrefetchStrategy{
		servicePatterns: map[string][]string{
			// Web services often need their backends
			"frontend": {"backend", "api", "auth"},
			"web":      {"api", "db", "cache", "auth"},
			"api":      {"db", "cache", "auth"},
			"gateway":  {"api", "auth", "rate-limiter"},

			// Microservices patterns
			"user":     {"auth", "db", "cache"},
			"auth":     {"user", "token", "cache"},
			"product":  {"inventory", "pricing", "db"},
			"cart":     {"product", "pricing", "user"},
			"checkout": {"cart", "payment", "inventory"},
			"payment":  {"auth", "notification"},

			// Infrastructure services
			"ingress": {"router", "auth", "rate-limiter"},
			"router":  {"api", "web", "metrics"},
			"metrics": {"prometheus", "grafana"},
			"logging": {"elasticsearch", "logstash"},

			// Data services
			"app":       {"db", "cache", "queue"},
			"worker":    {"queue", "db", "cache"},
			"scheduler": {"worker", "db"},

			// Common suffixes
			"-service":  {"-db", "-cache", "-api"},
			"-frontend": {"-backend", "-api", "-auth"},
			"-api":      {"-db", "-cache", "-auth"},
		},
		namespacePatterns: map[string][]string{
			// System namespaces
			"kube-system":  {"coredns", "kube-proxy", "metrics-server"},
			"monitoring":   {"prometheus", "grafana", "alertmanager"},
			"logging":      {"elasticsearch", "kibana", "fluentd"},
			"istio-system": {"istio-pilot", "istio-citadel", "istio-galley"},
		},
	}
}

// GetRelatedServices returns services likely to be queried together
func (ps *PrefetchStrategy) GetRelatedServices(service, namespace string) []string {
	var related []string
	seen := make(map[string]bool)

	// Extract base service name (remove common suffixes)
	baseName := extractBaseName(service)

	// Check exact matches
	if patterns, ok := ps.servicePatterns[baseName]; ok {
		for _, pattern := range patterns {
			fullName := pattern + "." + namespace + ".svc.cluster.local."
			if !seen[fullName] {
				related = append(related, fullName)
				seen[fullName] = true
			}
		}
	}

	// Check suffix patterns
	for suffix, patterns := range ps.servicePatterns {
		if strings.HasSuffix(baseName, suffix) {
			prefix := strings.TrimSuffix(baseName, suffix)
			for _, pattern := range patterns {
				fullName := prefix + pattern + "." + namespace + ".svc.cluster.local."
				if !seen[fullName] {
					related = append(related, fullName)
					seen[fullName] = true
				}
			}
		}
	}

	// Check namespace patterns
	if patterns, ok := ps.namespacePatterns[namespace]; ok {
		for _, pattern := range patterns {
			fullName := pattern + "." + namespace + ".svc.cluster.local."
			if !seen[fullName] && !strings.Contains(service, pattern) {
				related = append(related, fullName)
				seen[fullName] = true
			}
		}
	}

	// Add common infrastructure services from kube-system
	if namespace != "kube-system" {
		commonServices := []string{
			"kube-dns.kube-system.svc.cluster.local.",
			"metrics-server.kube-system.svc.cluster.local.",
		}
		for _, svc := range commonServices {
			if !seen[svc] {
				related = append(related, svc)
				seen[svc] = true
			}
		}
	}

	return related
}

// ShouldPrefetchType determines if a record type should be prefetched
func (ps *PrefetchStrategy) ShouldPrefetchType(currentType uint16, service string) []uint16 {
	// Always prefetch A and AAAA for dual-stack
	types := []uint16{dns.TypeA, dns.TypeAAAA}

	// If it's a service with ports, might need SRV
	if strings.Contains(service, "grpc") || strings.Contains(service, "http") {
		types = append(types, dns.TypeSRV)
	}

	return types
}

// extractBaseName removes common domain suffixes to get base service name
func extractBaseName(service string) string {
	// Remove FQDN suffix
	name := strings.TrimSuffix(service, ".svc.cluster.local.")
	name = strings.TrimSuffix(name, ".cluster.local.")

	// Get just the service name (not namespace)
	parts := strings.Split(name, ".")
	if len(parts) > 0 {
		return parts[0]
	}

	return name
}

// GetPrefetchPriority returns priority (0-1) for prefetching a service
func (ps *PrefetchStrategy) GetPrefetchPriority(service string, confidence float64) float64 {
	priority := confidence

	// Boost priority for critical services
	criticalServices := []string{
		"kube-dns", "coredns", "auth", "api-gateway",
		"ingress", "istio", "linkerd", "database", "cache",
	}

	baseName := extractBaseName(service)
	for _, critical := range criticalServices {
		if strings.Contains(baseName, critical) {
			priority *= 1.5 // 50% boost
			break
		}
	}

	// Cap at 1.0
	if priority > 1.0 {
		priority = 1.0
	}

	return priority
}
