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

	// demoLoaded is true when populateDemoData ran. In demo
	// mode the registry is ready synchronously and we can
	// answer authoritatively right away, regardless of the
	// live client's connection/sync state.
	demoLoaded bool

	// Bounded prefetch worker queue. Each cache/registry hit
	// used to `go prefetchPredictedWithClient(...)` unbounded,
	// so high QPS spawned one goroutine per query — prediction
	// takes locks, allocates, and sorts, so the backlog turned
	// the optimisation into a throughput bottleneck.
	prefetchCh      chan prefetchJob
	prefetchDropped uint64 // saturated-queue drops (stat)
}

// ready reports whether the middleware has data to answer
// authoritatively from. Demo mode seeds the registry up front;
// live mode must wait for informers to populate it. A live
// client whose NewClient failed leaves k.k8sClient == nil and
// demoLoaded == false — ready() returns false so ServeDNS
// passes the query through to downstream middleware instead
// of synthesising NXDOMAIN from an empty registry.
func (k *Kubernetes) ready() bool {
	if k.demoLoaded {
		return true
	}
	return k.k8sClient != nil && k.k8sClient.Synced()
}

type prefetchJob struct {
	clientIP string
	qname    string
	qtype    uint16
}

const (
	prefetchQueueSize = 1024
	prefetchWorkers   = 4
)

// New creates a new Kubernetes DNS middleware
func New(cfg *config.Config) *Kubernetes {
	// If Kubernetes integration is off and demo data isn't
	// requested, return a minimal pass-through middleware.
	if !cfg.Kubernetes.Enabled && !cfg.Kubernetes.Demo {
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
		registry.SetClusterDomain(clusterDomain)
		cache := NewZeroAllocCache()
		predictor := NewSmartPredictor()
		predictor.SetClusterDomain(clusterDomain)
		prefetchStrategy := NewPrefetchStrategy()
		prefetchStrategy.SetClusterDomain(clusterDomain)

		k = &Kubernetes{
			cache:            cache,
			registry:         registry,
			predictor:        predictor,
			prefetchStrategy: prefetchStrategy,
			killerMode:       true,
			clusterDomain:    clusterDomain,
			ttlConfig:        cfg.Kubernetes.TTL,
			prefetchCh:       make(chan prefetchJob, prefetchQueueSize),
		}

		for range prefetchWorkers {
			go k.prefetchWorker()
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

	// Try to connect to Kubernetes if enabled. An empty Kubeconfig
	// still works — NewClient / buildConfig falls through to
	// rest.InClusterConfig, so a pod with a service-account
	// kubeconfig (the in-cluster deployment case) picks up creds
	// automatically. Gating this on Kubeconfig != "" used to mean
	// an enabled+in-cluster deployment silently landed in the
	// demo-data path.
	if cfg.Kubernetes.Enabled {
		// Hand the client the registry ServeDNS reads from.
		// Killer mode uses the sharded registry; boring mode
		// uses the resolver's *Registry (which satisfies the
		// writer interface directly).
		var writer registryWriter
		if killerMode {
			writer = &shardedWriter{r: k.registry}
		} else {
			writer = k.resolver.registry
		}
		client, err := NewClient(cfg.Kubernetes.Kubeconfig, writer)
		if err != nil {
			zlog.Error("Failed to connect to Kubernetes API",
				zlog.String("error", err.Error()),
				zlog.String("kubeconfig", cfg.Kubernetes.Kubeconfig))
			// Don't fall back to demo data in this path: the
			// operator asked for live cluster integration, so
			// serving synthetic answers would look real and hide
			// the misconfiguration. The middleware effectively
			// no-ops until the client comes up.
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

	// Populate demo data only when the operator explicitly asked
	// for it via cfg.Kubernetes.Demo. An enabled-but-failed client
	// connection deliberately does NOT fall through to demo data:
	// serving synthesised answers would hide the misconfiguration
	// behind plausible-looking results.
	if cfg.Kubernetes.Demo {
		k.populateDemoData()
		k.demoLoaded = true
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

	// Even for cluster-domain queries, don't answer while the
	// registry is unpopulated — a failed live client or an
	// informer still warming up would otherwise turn into
	// authoritative NXDOMAIN for real cluster names.
	if !k.ready() {
		ch.Next(ctx)
		return
	}

	if k.killerMode {
		// KILLER MODE: Try TRUE zero-alloc cache first.
		//
		// Responses must go out through WriteMsg, not the raw
		// wire path. Upstream middleware (EDNS shaping, dnstap
		// response logging, reflex accounting, metrics) only
		// hooks WriteMsg — raw w.Write skipped all of them,
		// so killer-mode answers went out un-shaped and
		// un-observed.
		cachedWire := k.cache.GetEntry(qname, q.Qtype)
		if cachedWire != nil {
			atomic.AddUint64(&k.cacheHits, 1)

			cachedMsg := new(dns.Msg)
			if err := cachedMsg.Unpack(cachedWire); err == nil {
				cachedMsg.Id = req.Id
				if err := w.WriteMsg(cachedMsg); err != nil {
					atomic.AddUint64(&k.errors, 1)
					atomic.AddUint64(&k.writeErrors, 1)
					zlog.Error("Failed to write cached DNS response",
						zlog.String("query", qname),
						zlog.Int("qtype", int(q.Qtype)),
						zlog.String("error", err.Error()))
				}
			} else {
				atomic.AddUint64(&k.errors, 1)
				zlog.Error("Failed to unpack cached DNS response",
					zlog.String("query", qname),
					zlog.Int("qtype", int(q.Qtype)),
					zlog.String("error", err.Error()))
			}

			// Record for ML prediction with client IP
			clientIP := extractClientIP(w)
			k.predictor.Record(clientIP, qname, q.Qtype)

			// Trigger predictive prefetch via bounded queue.
			k.enqueuePrefetch(clientIP, qname, q.Qtype)

			return
		}

		// Use sharded registry for resolution
		answers, found := k.registry.ResolveQuery(qname, q.Qtype)
		if !found {
			ch.Next(ctx)
			return
		}

		// Build response. An empty answers slice means the name
		// exists but has no records of the requested type —
		// that's authoritative NOERROR/NODATA, not NXDOMAIN, so
		// leave the rcode at the SetReply default.
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		msg.RecursionAvailable = true
		msg.Answer = answers

		if err := w.WriteMsg(msg); err != nil {
			atomic.AddUint64(&k.errors, 1)
			atomic.AddUint64(&k.writeErrors, 1)
			zlog.Error("Failed to write DNS response",
				zlog.String("query", qname),
				zlog.Int("qtype", int(q.Qtype)),
				zlog.String("error", err.Error()))
			return
		}

		// Store packed wire in cache with appropriate TTL. If
		// packing fails we just skip caching — the response
		// already went out above.
		if wire, err := msg.Pack(); err == nil {
			ttl := uint32(CacheDefaultTTL) // Default TTL
			if len(answers) > 0 {
				if h := answers[0].Header(); h != nil {
					ttl = h.Ttl
				}
			}
			k.cache.StoreWire(qname, q.Qtype, wire, ttl)
		} else {
			atomic.AddUint64(&k.errors, 1)
			atomic.AddUint64(&k.packErrors, 1)
			zlog.Error("Failed to pack DNS message for cache",
				zlog.String("query", qname),
				zlog.Int("qtype", int(q.Qtype)),
				zlog.String("error", err.Error()))
		}

		// Record for ML with client IP
		clientIP := extractClientIP(w)
		k.predictor.Record(clientIP, qname, q.Qtype)

		// Trigger predictive prefetch via bounded queue.
		k.enqueuePrefetch(clientIP, qname, q.Qtype)
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
		k.resolver.registry.AddService(&Service{ //nolint:gosec // G104 - service registration
			Name:       "kubernetes",
			Namespace:  "default",
			ClusterIPs: [][]byte{net.ParseIP("10.96.0.1").To4()},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "https", Port: PortHTTPS, Protocol: "TCP"},
			},
		})

		k.resolver.registry.AddService(&Service{ //nolint:gosec // G104 - service registration
			Name:       "kube-dns",
			Namespace:  "kube-system",
			ClusterIPs: [][]byte{net.ParseIP("10.96.0.10").To4()},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "dns", Port: PortDNS, Protocol: "UDP"},
				{Name: "dns-tcp", Port: PortDNS, Protocol: "TCP"},
			},
		})

		k.resolver.registry.AddService(&Service{ //nolint:gosec // G104 - service registration
			Name:      "headless",
			Namespace: "default",
			Type:      "ClusterIP",
			Headless:  true,
		})

		k.resolver.registry.SetEndpoints("headless", "default", []Endpoint{ //nolint:gosec // G104 - service registration
			{Addresses: []string{"10.244.1.10"}, Ready: true},
			{Addresses: []string{"10.244.1.11"}, Ready: true},
		})

		k.resolver.registry.AddService(&Service{ //nolint:gosec // G104 - service registration
			Name:         "external",
			Namespace:    "default",
			Type:         "ExternalName",
			ExternalName: "example.com",
		})

		k.resolver.registry.AddPod(&Pod{ //nolint:gosec // G104 - service registration
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

// enqueuePrefetch offers a prefetch job to the bounded worker
// pool via a non-blocking send. If the queue is full we drop
// the job and bump a counter rather than spawning yet another
// goroutine or blocking the serving path — prefetch is a
// best-effort optimisation.
func (k *Kubernetes) enqueuePrefetch(clientIP, qname string, qtype uint16) {
	if k.prefetchCh == nil {
		return
	}
	select {
	case k.prefetchCh <- prefetchJob{clientIP: clientIP, qname: qname, qtype: qtype}:
	default:
		atomic.AddUint64(&k.prefetchDropped, 1)
	}
}

// prefetchWorker drains the prefetch queue.
func (k *Kubernetes) prefetchWorker() {
	for job := range k.prefetchCh {
		k.prefetchPredictedWithClient(job.clientIP, job.qname, job.qtype)
	}
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
