// Package kubernetes provides a Kubernetes DNS middleware for SDNS
package kubernetes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog"
)

// Kubernetes middleware for DNS resolution
type Kubernetes struct {
	// Standard components
	resolver  *Resolver
	k8sClient *Client

	// KILLER PERFORMANCE COMPONENTS
	cache     *ZeroAllocCache    // Zero-allocation cache
	registry  *ShardedRegistry   // Lock-free sharded registry
	predictor *LockFreePredictor // ML-based predictor

	// Configuration
	killerMode    bool
	clusterDomain string

	// Stats
	queries   uint64
	cacheHits uint64
}

// New creates a new Kubernetes DNS middleware
func New(cfg *config.Config) *Kubernetes {
	// If Kubernetes is not enabled, return nil
	if !cfg.Kubernetes.Enabled {
		return nil
	}

	// Use configuration from config file
	clusterDomain := cfg.Kubernetes.ClusterDomain
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}

	// Validate cluster domain format
	if !strings.HasSuffix(clusterDomain, ".local") && !strings.HasSuffix(clusterDomain, ".cluster") {
		zlog.Warn("Non-standard cluster domain", zlog.String("domain", clusterDomain))
	}

	killerMode := cfg.Kubernetes.KillerMode

	var k *Kubernetes

	if killerMode {
		// KILLER MODE: Maximum performance
		registry := NewShardedRegistry()
		cache := NewZeroAllocCache()
		predictor := NewLockFreePredictor()

		k = &Kubernetes{
			cache:         cache,
			registry:      registry,
			predictor:     predictor,
			killerMode:    true,
			clusterDomain: clusterDomain,
		}

		// Create resolver (just for demo data population)
		k.resolver = &Resolver{
			clusterDomain: clusterDomain,
			registry:      NewRegistry(),
		}

		// Pre-warm cache for common services
		cache.Prewarm(
			[]string{"kube-dns", "kubernetes", "metrics-server", "coredns"},
			[]string{"kube-system", "default"},
			clusterDomain,
		)

		// Start ML prediction loop
		go k.predictionLoop()
	} else {
		// Boring mode
		standardCache := NewCache()
		k = &Kubernetes{
			clusterDomain: clusterDomain,
		}

		// Create standard resolver
		k.resolver = NewResolver(clusterDomain, standardCache)
	}

	// Try to connect to Kubernetes if enabled
	if cfg.Kubernetes.Enabled && cfg.Kubernetes.Kubeconfig != "" {
		client, err := NewClient(cfg.Kubernetes.Kubeconfig)
		if err != nil {
			zlog.Warn("Failed to connect to Kubernetes, using demo mode", zlog.String("error", err.Error()))
			// Continue without K8s - useful for testing
		} else {
			k.k8sClient = client
			go client.Run(context.Background())
		}
	}

	// If no K8s client, populate demo data
	if k.k8sClient == nil {
		k.populateDemoData()
	}

	zlog.Info("Kubernetes DNS middleware initialized",
		zlog.String("cluster_domain", clusterDomain),
		zlog.Bool("k8s_connected", k.k8sClient != nil),
		zlog.Bool("killer_mode", killerMode))

	return k
}

// Name returns the middleware name
func (k *Kubernetes) Name() string {
	return "kubernetes"
}

// ServeDNS handles DNS queries
func (k *Kubernetes) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	atomic.AddUint64(&k.queries, 1)

	if len(req.Question) == 0 {
		ch.Next(ctx)
		return
	}

	q := req.Question[0]
	qname := strings.ToLower(q.Name)

	// Check if it's our domain or a reverse query
	isReverse := strings.HasSuffix(qname, ".in-addr.arpa.") || strings.HasSuffix(qname, ".ip6.arpa.")
	if !strings.HasSuffix(qname, "."+k.clusterDomain+".") && !isReverse {
		ch.Next(ctx)
		return
	}

	if k.killerMode {
		// KILLER MODE: Try zero-alloc cache first
		if wire := k.cache.Get(qname, q.Qtype, req.Id); wire != nil {
			atomic.AddUint64(&k.cacheHits, 1)

			// Direct wire format write - ZERO ALLOCATIONS!
			w.Write(wire)

			// Record for ML prediction
			k.predictor.Record(qname, q.Qtype)

			// Trigger predictive prefetch
			go k.prefetchPredicted(qname)

			return
		}

		// Use sharded registry for resolution
		answers, found := k.registry.ResolveQuery(qname, q.Qtype)
		if !found {
			ch.Next(ctx)
			return
		}

		// Build response
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		msg.RecursionAvailable = true

		if len(answers) > 0 {
			msg.Answer = answers
		} else {
			msg.SetRcode(req, dns.RcodeNameError)
		}

		w.WriteMsg(msg)

		// Cache in wire format
		k.cache.Store(qname, q.Qtype, msg)

		// Record for ML
		k.predictor.Record(qname, q.Qtype)
	} else {
		// Boring mode - use resolver which has its own cache
		resp, found := k.resolver.Resolve(qname, q.Qtype)
		if !found {
			ch.Next(ctx)
			return
		}

		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		msg.RecursionAvailable = true

		if resp.Rcode == dns.RcodeSuccess {
			msg.Answer = resp.Answer
			msg.Extra = resp.Extra
		} else {
			msg.SetRcode(req, resp.Rcode)
		}

		w.WriteMsg(msg)
	}
}

// populateDemoData adds demo services for testing
func (k *Kubernetes) populateDemoData() {
	if k.killerMode {
		// Killer mode - use sharded registry
		k.registry.AddService(&Service{
			Name:       "kubernetes",
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, 0, 1}},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "https", Port: 443, Protocol: "tcp"},
			},
		})

		k.registry.AddService(&Service{
			Name:       "kube-dns",
			Namespace:  "kube-system",
			ClusterIPs: [][]byte{{10, 96, 0, 10}},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "dns", Port: 53, Protocol: "udp"},
				{Name: "dns-tcp", Port: 53, Protocol: "tcp"},
			},
		})

		// Add more services for killer benchmarks
		for i := 1; i <= 10; i++ {
			k.registry.AddService(&Service{
				Name:       fmt.Sprintf("app-%d", i),
				Namespace:  "production",
				ClusterIPs: [][]byte{{10, 96, 1, byte(i)}},
				IPFamilies: []string{"IPv4"},
			})
		}

		// Add test services for prediction tests
		k.registry.AddService(&Service{
			Name:       "app",
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, 2, 1}},
			IPFamilies: []string{"IPv4"},
		})

		k.registry.AddService(&Service{
			Name:       "db",
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, 2, 2}},
			IPFamilies: []string{"IPv4"},
		})

		k.registry.AddService(&Service{
			Name:       "cache",
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, 2, 3}},
			IPFamilies: []string{"IPv4"},
		})

		// Add headless service
		k.registry.AddService(&Service{
			Name:      "headless",
			Namespace: "default",
			Headless:  true,
		})

		// Add external service
		k.registry.AddService(&Service{
			Name:         "external",
			Namespace:    "default",
			Type:         "ExternalName",
			ExternalName: "example.com",
		})

		// Add nginx service for StatefulSet
		k.registry.AddService(&Service{
			Name:      "nginx",
			Namespace: "default",
			Headless:  true,
		})

		// Add pods
		k.registry.AddPod(&Pod{
			Name:      "web-0",
			Namespace: "default",
			IPs:       []string{"10.244.1.10"},
			Hostname:  "web-0",
			Subdomain: "nginx",
		})
	} else {
		// Boring mode - use standard registry
		k.resolver.registry.AddService(&Service{
			Name:       "kubernetes",
			Namespace:  "default",
			ClusterIPs: [][]byte{net.ParseIP("10.96.0.1").To4()},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "https", Port: 443, Protocol: "TCP"},
			},
		})

		k.resolver.registry.AddService(&Service{
			Name:       "kube-dns",
			Namespace:  "kube-system",
			ClusterIPs: [][]byte{net.ParseIP("10.96.0.10").To4()},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "dns", Port: 53, Protocol: "UDP"},
				{Name: "dns-tcp", Port: 53, Protocol: "TCP"},
			},
		})

		k.resolver.registry.AddService(&Service{
			Name:      "headless",
			Namespace: "default",
			Type:      "ClusterIP",
			Headless:  true,
		})

		k.resolver.registry.SetEndpoints("headless", "default", []Endpoint{
			{Addresses: []string{"10.244.1.10"}, Ready: true},
			{Addresses: []string{"10.244.1.11"}, Ready: true},
		})

		k.resolver.registry.AddService(&Service{
			Name:         "external",
			Namespace:    "default",
			Type:         "ExternalName",
			ExternalName: "example.com",
		})

		k.resolver.registry.AddPod(&Pod{
			Name:      "web-0",
			Namespace: "default",
			IPs:       []string{"10.244.1.10"},
			Hostname:  "web-0",
			Subdomain: "nginx",
		})
	}
}

// Stats returns statistics
func (k *Kubernetes) Stats() map[string]interface{} {
	queries := atomic.LoadUint64(&k.queries)
	hits := atomic.LoadUint64(&k.cacheHits)

	hitRate := float64(0)
	if queries > 0 {
		hitRate = float64(hits) / float64(queries) * 100
	}

	stats := map[string]interface{}{
		"queries":      queries,
		"cache_hits":   hits,
		"cache_misses": queries - hits,
		"hit_rate":     hitRate,
		"killer_mode":  k.killerMode,
	}

	if k.killerMode {
		if k.cache != nil {
			stats["cache"] = k.cache.Stats()
		}
		if k.predictor != nil {
			stats["predictor"] = k.predictor.Stats()
		}
		if k.registry != nil {
			stats["registry"] = k.registry.GetStats()
		}
	} else if k.resolver != nil && k.resolver.registry != nil {
		stats["registry"] = k.resolver.registry.Stats()
	}

	return stats
}

// prefetchPredicted pre-fetches queries based on ML predictions
func (k *Kubernetes) prefetchPredicted(current string) {
	if !k.killerMode {
		return
	}

	predictions := k.predictor.Predict(current)
	for _, predicted := range predictions {
		// Check if already cached
		if wire := k.cache.Get(predicted, dns.TypeA, 0); wire != nil {
			continue
		}

		// Resolve and cache
		if answers, found := k.registry.ResolveQuery(predicted, dns.TypeA); found && len(answers) > 0 {
			msg := new(dns.Msg)
			msg.SetQuestion(predicted, dns.TypeA)
			msg.Response = true
			msg.Authoritative = true
			msg.Answer = answers

			k.cache.Store(predicted, dns.TypeA, msg)
		}
	}
}

// predictionLoop runs periodic prediction optimization
func (k *Kubernetes) predictionLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := k.Stats()
		zlog.Info("Kubernetes DNS performance",
			zlog.Any("stats", stats),
			zlog.String("mode", "KILLER"),
		)
	}
}
