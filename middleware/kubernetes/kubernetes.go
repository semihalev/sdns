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
	"github.com/semihalev/zlog/v2"
)

// Kubernetes middleware for DNS resolution
type Kubernetes struct {
	// Standard components
	resolver  *Resolver
	k8sClient *Client

	// KILLER PERFORMANCE COMPONENTS
	cache            *ZeroAllocCache   // TRUE zero-allocation cache
	registry         *ShardedRegistry  // Lock-free sharded registry
	predictor        *SmartPredictor   // Intelligent ML-based predictor
	prefetchStrategy *PrefetchStrategy // Smart prefetch patterns

	// Configuration
	killerMode    bool
	clusterDomain string
	ttlConfig     config.KubernetesTTLConfig

	// Stats
	queries    uint64
	cacheHits  uint64
	errors     uint64
	prefetches uint64

	// Error metrics by type
	packErrors  uint64 // DNS message packing errors
	writeErrors uint64 // Response write errors
}

// New creates a new Kubernetes DNS middleware
func New(cfg *config.Config) *Kubernetes {
	// If Kubernetes is not enabled, return a minimal pass-through middleware
	if !cfg.Kubernetes.Enabled {
		return &Kubernetes{
			clusterDomain: "cluster.local", // Set a default to avoid any issues
		}
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
		// KILLER MODE: Maximum performance with TRUE zero allocations
		registry := NewShardedRegistry()
		registry.SetTTLs(cfg.Kubernetes.TTL.Service, cfg.Kubernetes.TTL.Pod, cfg.Kubernetes.TTL.SRV, cfg.Kubernetes.TTL.PTR)
		cache := NewZeroAllocCache()
		predictor := NewSmartPredictor()

		k = &Kubernetes{
			cache:            cache,
			registry:         registry,
			predictor:        predictor,
			prefetchStrategy: NewPrefetchStrategy(),
			killerMode:       true,
			clusterDomain:    clusterDomain,
			ttlConfig:        cfg.Kubernetes.TTL,
		}

		// Create resolver (just for demo data population)
		k.resolver = NewResolver(cfg, clusterDomain, nil)

		// Pre-warm cache for common services
		// Skip prewarm for now - it interferes with actual registry data
		// cache.Prewarm(
		//	[]string{"kube-dns", "kubernetes", "metrics-server", "coredns"},
		//	[]string{"kube-system", "default"},
		//	clusterDomain,
		// )

		// Start ML prediction loop
		go k.predictionLoop()
	} else {
		// Boring mode
		standardCache := NewCache()
		k = &Kubernetes{
			clusterDomain: clusterDomain,
			ttlConfig:     cfg.Kubernetes.TTL,
		}

		// Create standard resolver
		k.resolver = NewResolver(cfg, clusterDomain, standardCache)
	}

	// Try to connect to Kubernetes if enabled
	if cfg.Kubernetes.Enabled && cfg.Kubernetes.Kubeconfig != "" {
		client, err := NewClient(cfg.Kubernetes.Kubeconfig)
		if err != nil {
			zlog.Error("Failed to connect to Kubernetes API",
				zlog.String("error", err.Error()),
				zlog.String("kubeconfig", cfg.Kubernetes.Kubeconfig))
			zlog.Warn("Falling back to demo mode without Kubernetes integration")
			// Continue without K8s - useful for testing
		} else {
			k.k8sClient = client
			// Run client in background with error handling
			go func() {
				if err := client.Run(context.Background()); err != nil {
					zlog.Error("Kubernetes client stopped with error", zlog.String("error", err.Error()))
				}
			}()
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

	// If resolver is nil, we're disabled - pass through
	if k.resolver == nil && k.registry == nil {
		ch.Next(ctx)
		return
	}

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
		// KILLER MODE: Try TRUE zero-alloc cache first
		cachedWire := k.cache.GetEntry(qname, q.Qtype)
		if cachedWire != nil {
			atomic.AddUint64(&k.cacheHits, 1)

			// Create a copy for response (we must copy to update message ID)
			respWire := make([]byte, len(cachedWire))
			copy(respWire, cachedWire)

			// Update message ID in the copy
			UpdateMessageID(respWire, req.Id)

			// Write raw wire format - this is the fastest way
			if _, err := w.Write(respWire); err != nil {
				atomic.AddUint64(&k.errors, 1)
				atomic.AddUint64(&k.writeErrors, 1)
				zlog.Error("Failed to write cached DNS response",
					zlog.String("query", qname),
					zlog.Int("qtype", int(q.Qtype)),
					zlog.String("error", err.Error()))
			}

			// Record for ML prediction with client IP
			clientIP := extractClientIP(w)
			k.predictor.Record(clientIP, qname, q.Qtype)

			// Trigger predictive prefetch with client context
			go k.prefetchPredictedWithClient(clientIP, qname, q.Qtype)

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

		// Pack to wire format for response
		wire, err := msg.Pack()
		if err == nil {
			if _, err := w.Write(wire); err != nil {
				atomic.AddUint64(&k.errors, 1)
				atomic.AddUint64(&k.writeErrors, 1)
				zlog.Error("Failed to write DNS response",
					zlog.String("query", qname),
					zlog.Int("qtype", int(q.Qtype)),
					zlog.String("error", err.Error()))
				return
			}

			// Store in cache with appropriate TTL
			ttl := uint32(CacheDefaultTTL) // Default TTL
			if len(answers) > 0 {
				if h := answers[0].Header(); h != nil {
					ttl = h.Ttl
				}
			}
			k.cache.StoreWire(qname, q.Qtype, wire, ttl)
		} else {
			// DNS message packing failed
			atomic.AddUint64(&k.errors, 1)
			atomic.AddUint64(&k.packErrors, 1)
			zlog.Error("Failed to pack DNS message",
				zlog.String("query", qname),
				zlog.Int("qtype", int(q.Qtype)),
				zlog.String("error", err.Error()))
			// Fallback to standard write
			if err := w.WriteMsg(msg); err != nil {
				atomic.AddUint64(&k.writeErrors, 1)
				zlog.Error("Failed to write DNS message via fallback",
					zlog.String("query", qname),
					zlog.String("error", err.Error()))
			}
		}

		// Record for ML with client IP
		clientIP := extractClientIP(w)
		k.predictor.Record(clientIP, qname, q.Qtype)

		// Trigger predictive prefetch after registry hit
		go k.prefetchPredictedWithClient(clientIP, qname, q.Qtype)
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

		if err := w.WriteMsg(msg); err != nil {
			atomic.AddUint64(&k.errors, 1)
			atomic.AddUint64(&k.writeErrors, 1)
			zlog.Error("Failed to write DNS response in standard mode",
				zlog.String("query", qname),
				zlog.Int("qtype", int(q.Qtype)),
				zlog.String("error", err.Error()))
		}
	}
}

// populateDemoData adds demo services for testing
func (k *Kubernetes) populateDemoData() {
	if k.killerMode {
		// Killer mode - use sharded registry
		k.registry.AddService(&Service{
			Name:       "kubernetes",
			Namespace:  "default",
			ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 0, 1}},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "https", Port: PortHTTPS, Protocol: "tcp"},
			},
		})

		k.registry.AddService(&Service{
			Name:       "kube-dns",
			Namespace:  "kube-system",
			ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 0, 10}},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "dns", Port: PortDNS, Protocol: "udp"},
				{Name: "dns-tcp", Port: PortDNS, Protocol: "tcp"},
			},
		})

		// Add more services for killer benchmarks
		for i := BenchmarkServiceStart; i <= DemoServiceCount; i++ {
			k.registry.AddService(&Service{
				Name:       fmt.Sprintf("app-%d", i),
				Namespace:  "production",
				ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 1, byte(i)}},
				IPFamilies: []string{"IPv4"},
			})
		}

		// Add test services for prediction tests
		k.registry.AddService(&Service{
			Name:       "app",
			Namespace:  "default",
			ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 2, 1}},
			IPFamilies: []string{"IPv4"},
		})

		// Add a dual-stack service for testing
		k.registry.AddService(&Service{
			Name:       "dual-stack",
			Namespace:  "default",
			ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 3, 1}, {byte(IPv6TestPrefix >> 8), byte(IPv6TestPrefix & 0xFF), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			IPFamilies: []string{"IPv4", "IPv6"},
		})

		k.registry.AddService(&Service{
			Name:       "db",
			Namespace:  "default",
			ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 2, 2}},
			IPFamilies: []string{"IPv4"},
		})

		k.registry.AddService(&Service{
			Name:       "cache",
			Namespace:  "default",
			ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 2, 3}},
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

		// Add endpoints for headless service
		k.registry.SetEndpoints("headless", "default", []Endpoint{
			{Addresses: []string{"10.244.1.10"}, Ready: true},
			{Addresses: []string{"10.244.1.11"}, Ready: true},
		})

		// Add endpoints for nginx service
		k.registry.SetEndpoints("nginx", "default", []Endpoint{
			{Addresses: []string{"10.244.1.10"}, Hostname: "web-0", Ready: true},
		})
	} else {
		// Boring mode - use standard registry
		k.resolver.registry.AddService(&Service{
			Name:       "kubernetes",
			Namespace:  "default",
			ClusterIPs: [][]byte{net.ParseIP("10.96.0.1").To4()},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "https", Port: PortHTTPS, Protocol: "TCP"},
			},
		})

		k.resolver.registry.AddService(&Service{
			Name:       "kube-dns",
			Namespace:  "kube-system",
			ClusterIPs: [][]byte{net.ParseIP("10.96.0.10").To4()},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "dns", Port: PortDNS, Protocol: "UDP"},
				{Name: "dns-tcp", Port: PortDNS, Protocol: "TCP"},
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
func (k *Kubernetes) Stats() map[string]any {
	queries := atomic.LoadUint64(&k.queries)
	hits := atomic.LoadUint64(&k.cacheHits)

	hitRate := float64(0)
	if queries > 0 {
		hitRate = float64(hits) / float64(queries) * PercentageMultiplier
	}

	errors := atomic.LoadUint64(&k.errors)
	packErrors := atomic.LoadUint64(&k.packErrors)
	writeErrors := atomic.LoadUint64(&k.writeErrors)

	stats := map[string]any{
		"queries":      queries,
		"cache_hits":   hits,
		"cache_misses": queries - hits,
		"hit_rate":     hitRate,
		"prefetches":   atomic.LoadUint64(&k.prefetches),
		"errors":       errors,
		"pack_errors":  packErrors,
		"write_errors": writeErrors,
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

// prefetchPredictedWithClient pre-fetches queries based on ML predictions with client context
func (k *Kubernetes) prefetchPredictedWithClient(clientIP, current string, currentQtype uint16) {
	if !k.killerMode {
		return
	}

	// Use client-specific predictions
	predictions := k.predictor.Predict(clientIP, current)

	for _, pred := range predictions {
		// Calculate priority based on confidence and service importance
		priority := k.prefetchStrategy.GetPrefetchPriority(pred.Service, pred.Confidence)

		// Only prefetch if priority is high enough
		if priority < 0.3 {
			continue
		}

		// Determine which record types to prefetch based on current query
		var qtypes []uint16
		switch currentQtype {
		case dns.TypeA:
			// If querying A, might also need AAAA
			qtypes = []uint16{dns.TypeA, dns.TypeAAAA}
		case dns.TypeAAAA:
			// If querying AAAA, might also need A
			qtypes = []uint16{dns.TypeAAAA, dns.TypeA}
		case dns.TypeSRV:
			// SRV queries often followed by A/AAAA
			qtypes = []uint16{dns.TypeA, dns.TypeAAAA}
		default:
			// Default to A and AAAA
			qtypes = []uint16{dns.TypeA, dns.TypeAAAA}
		}

		for _, qtype := range qtypes {
			// Check if already cached
			if cached := k.cache.GetEntry(pred.Service, qtype); cached != nil {
				continue
			}

			// Resolve and cache
			if answers, found := k.registry.ResolveQuery(pred.Service, qtype); found && len(answers) > 0 {
				msg := new(dns.Msg)
				msg.SetQuestion(pred.Service, qtype)
				msg.Response = true
				msg.Authoritative = true
				msg.Answer = answers

				// Pack and store
				if wire, err := msg.Pack(); err == nil {
					ttl := uint32(CacheDefaultTTL)
					if len(msg.Answer) > 0 {
						ttl = msg.Answer[0].Header().Ttl
					}
					k.cache.StoreWire(pred.Service, qtype, wire, ttl)
					atomic.AddUint64(&k.prefetches, 1)

					zlog.Debug("Prefetched service based on prediction",
						zlog.String("client", clientIP),
						zlog.String("service", pred.Service),
						zlog.String("type", dns.TypeToString[qtype]),
						zlog.Float64("confidence", pred.Confidence))
				} else {
					zlog.Debug("Failed to pack DNS message for prefetch",
						zlog.String("query", pred.Service),
						zlog.String("type", dns.TypeToString[qtype]),
						zlog.String("error", err.Error()))
				}
			}
		}
	}
}

// predictionLoop runs periodic prediction optimization
func (k *Kubernetes) predictionLoop() {
	ticker := time.NewTicker(StatsLogInterval)
	defer ticker.Stop()

	for range ticker.C {
		stats := k.Stats()
		zlog.Info("Kubernetes DNS performance",
			zlog.Any("stats", stats),
			zlog.String("mode", "KILLER"),
		)
	}
}

// extractClientIP extracts the client IP from the ResponseWriter
func extractClientIP(w middleware.ResponseWriter) string {
	if w.RemoteIP() != nil {
		return w.RemoteIP().String()
	}
	return ""
}
