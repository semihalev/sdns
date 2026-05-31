// Package kubernetes provides a Kubernetes DNS middleware for SDNS.
// It answers cluster-domain queries (services, pods, SRV, PTR) from
// a sharded in-memory registry populated by Kubernetes informers.
// ResolveQuery is a single sharded map lookup plus a slice-header
// copy — zero allocations per query.
package kubernetes

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// Kubernetes is the DNS middleware that answers cluster-domain queries.
type Kubernetes struct {
	registry  *Registry
	k8sClient *Client

	clusterDomain string
	ttlConfig     config.KubernetesTTLConfig

	// demoLoaded is true when populateDemoData seeded the registry
	// synchronously, bypassing informer sync state.
	demoLoaded bool

	queries     uint64
	answered    uint64
	errors      uint64
	writeErrors uint64
}

// ready reports whether the registry has data to answer from. An
// enabled-but-failed client leaves the middleware effectively
// no-op until the client comes up.
func (k *Kubernetes) ready() bool {
	if k.demoLoaded {
		return true
	}
	return k.k8sClient != nil && k.k8sClient.Synced()
}

// New creates a new Kubernetes DNS middleware.
func New(cfg *config.Config) *Kubernetes {
	if !cfg.Kubernetes.Enabled && !cfg.Kubernetes.Demo {
		return &Kubernetes{clusterDomain: "cluster.local"}
	}

	if cfg.Kubernetes.KillerMode {
		zlog.Warn("kubernetes.killer_mode is deprecated and now a no-op — remove the field from your config")
	}

	// Normalise so suffix matching works regardless of how the
	// operator wrote the value (trailing dot, mixed case).
	clusterDomain := strings.TrimSuffix(strings.ToLower(cfg.Kubernetes.ClusterDomain), ".")
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	if !strings.HasSuffix(clusterDomain, ".local") && !strings.HasSuffix(clusterDomain, ".cluster") {
		zlog.Warn("Non-standard cluster domain", zlog.String("domain", clusterDomain))
	}

	registry := NewRegistry()
	registry.SetTTLs(cfg.Kubernetes.TTL.Service, cfg.Kubernetes.TTL.Pod, cfg.Kubernetes.TTL.SRV, cfg.Kubernetes.TTL.PTR)
	registry.SetClusterDomain(clusterDomain)

	k := &Kubernetes{
		registry:      registry,
		clusterDomain: clusterDomain,
		ttlConfig:     cfg.Kubernetes.TTL,
	}

	if cfg.Kubernetes.Enabled {
		client, err := NewClient(cfg.Kubernetes.Kubeconfig, k.registry)
		if err != nil {
			// Deliberate: don't fall back to demo data on a
			// live-integration failure — synthetic answers
			// would hide the misconfiguration.
			zlog.Error("Failed to connect to Kubernetes API",
				zlog.String("error", err.Error()),
				zlog.String("kubeconfig", cfg.Kubernetes.Kubeconfig))
		} else {
			k.k8sClient = client
			go func() {
				if err := client.Run(context.Background()); err != nil {
					zlog.Error("Kubernetes client stopped with error", zlog.String("error", err.Error()))
				}
			}()
		}
	}

	if cfg.Kubernetes.Demo {
		k.populateDemoData()
		k.demoLoaded = true
	}

	zlog.Info("Kubernetes DNS middleware initialized",
		zlog.String("cluster_domain", clusterDomain),
		zlog.Bool("k8s_connected", k.k8sClient != nil))

	return k
}

// Name returns the middleware name.
func (k *Kubernetes) Name() string { return "kubernetes" }

// ServeDNS handles DNS queries.
func (k *Kubernetes) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if k.registry == nil {
		ch.Next(ctx)
		return
	}

	atomic.AddUint64(&k.queries, 1)
	kubernetesQueries.Inc()

	if len(req.Question) == 0 {
		ch.Next(ctx)
		return
	}

	q := req.Question[0]
	qname := strings.ToLower(q.Name)

	isReverse := strings.HasSuffix(qname, ".in-addr.arpa.") || strings.HasSuffix(qname, ".ip6.arpa.")
	if !strings.HasSuffix(qname, "."+k.clusterDomain+".") && !isReverse {
		ch.Next(ctx)
		return
	}

	// Unsynced cluster-domain queries SERVFAIL rather than fall
	// through — falling through would leak internal names to
	// public DNS. Reverse-zone queries still pass through since we
	// don't claim authority over in-addr.arpa / ip6.arpa.
	if !k.ready() {
		if isReverse {
			ch.Next(ctx)
			return
		}
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.RecursionAvailable = true
		msg.Rcode = dns.RcodeServerFailure
		if err := w.WriteMsg(msg); err != nil {
			atomic.AddUint64(&k.errors, 1)
			atomic.AddUint64(&k.writeErrors, 1)
			kubernetesErrors.Inc()
			kubernetesWriteErrors.Inc()
			zlog.Error("Failed to write SERVFAIL for unsynced cluster query",
				zlog.String("query", qname),
				zlog.String("error", err.Error()))
			return
		}
		atomic.AddUint64(&k.answered, 1)
		kubernetesAnswered.Inc()
		return
	}

	answers, extra, found := k.registry.ResolveQuery(qname, q.Qtype)
	if !found {
		// Cluster-domain misses are authoritative NXDOMAIN;
		// reverse-zone misses fall through (we can't tell a
		// pod/service IP from a public one).
		if isReverse {
			ch.Next(ctx)
			return
		}
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		msg.RecursionAvailable = true
		msg.Rcode = dns.RcodeNameError
		if err := w.WriteMsg(msg); err != nil {
			atomic.AddUint64(&k.errors, 1)
			atomic.AddUint64(&k.writeErrors, 1)
			kubernetesErrors.Inc()
			kubernetesWriteErrors.Inc()
			zlog.Error("Failed to write DNS response",
				zlog.String("query", qname),
				zlog.Int("qtype", int(q.Qtype)),
				zlog.String("error", err.Error()))
			return
		}
		atomic.AddUint64(&k.answered, 1)
		kubernetesAnswered.Inc()
		return
	}

	// Empty answers slice == authoritative NOERROR/NODATA.
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = true
	msg.Answer = answers
	msg.Extra = append(msg.Extra, extra...)

	if err := w.WriteMsg(msg); err != nil {
		atomic.AddUint64(&k.errors, 1)
		atomic.AddUint64(&k.writeErrors, 1)
		kubernetesErrors.Inc()
		kubernetesWriteErrors.Inc()
		zlog.Error("Failed to write DNS response",
			zlog.String("query", qname),
			zlog.Int("qtype", int(q.Qtype)),
			zlog.String("error", err.Error()))
		return
	}
	atomic.AddUint64(&k.answered, 1)
	kubernetesAnswered.Inc()
}

// populateDemoData seeds representative services / pods for the
// Demo config flag.
func (k *Kubernetes) populateDemoData() {
	k.registry.AddService(&Service{
		Name:       "kubernetes",
		Namespace:  "default",
		ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 0, 1}},
		IPFamilies: []string{"IPv4"},
		Ports:      []Port{{Name: "https", Port: PortHTTPS, Protocol: "tcp"}},
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

	for i := BenchmarkServiceStart; i <= DemoServiceCount; i++ {
		k.registry.AddService(&Service{
			Name:       fmt.Sprintf("app-%d", i),
			Namespace:  "production",
			ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 1, byte(i)}},
			IPFamilies: []string{"IPv4"},
		})
	}

	k.registry.AddService(&Service{
		Name:       "app",
		Namespace:  "default",
		ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 2, 1}},
		IPFamilies: []string{"IPv4"},
	})

	k.registry.AddService(&Service{
		Name: "dual-stack", Namespace: "default",
		ClusterIPs: [][]byte{
			{NetworkOctet10, NetworkOctet96, 3, 1},
			{byte(IPv6TestPrefix >> 8), byte(IPv6TestPrefix & 0xFF), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		IPFamilies: []string{"IPv4", "IPv6"},
	})

	k.registry.AddService(&Service{
		Name: "db", Namespace: "default",
		ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 2, 2}},
		IPFamilies: []string{"IPv4"},
	})

	k.registry.AddService(&Service{
		Name: "cache", Namespace: "default",
		ClusterIPs: [][]byte{{NetworkOctet10, NetworkOctet96, 2, 3}},
		IPFamilies: []string{"IPv4"},
	})

	k.registry.AddService(&Service{Name: "headless", Namespace: "default", Headless: true})
	k.registry.AddService(&Service{Name: "external", Namespace: "default", Type: "ExternalName", ExternalName: "example.com"})
	k.registry.AddService(&Service{Name: "nginx", Namespace: "default", Headless: true})

	k.registry.AddPod(&Pod{
		Name: "web-0", Namespace: "default",
		IPs: []string{"10.244.1.10"}, Hostname: "web-0", Subdomain: "nginx",
	})

	k.registry.SetEndpoints("headless", "default", []Endpoint{
		{Addresses: []string{"10.244.1.10"}, Ready: true},
		{Addresses: []string{"10.244.1.11"}, Ready: true},
	})
	k.registry.SetEndpoints("nginx", "default", []Endpoint{
		{Addresses: []string{"10.244.1.10"}, Hostname: "web-0", Ready: true},
	})
}

// Stats returns runtime statistics.
func (k *Kubernetes) Stats() map[string]any {
	queries := atomic.LoadUint64(&k.queries)
	answered := atomic.LoadUint64(&k.answered)
	stats := map[string]any{
		"queries":      queries,
		"answered":     answered,
		"errors":       atomic.LoadUint64(&k.errors),
		"write_errors": atomic.LoadUint64(&k.writeErrors),
	}
	if k.registry != nil {
		stats["registry"] = k.registry.Stats()
	}
	return stats
}
