package kubernetes

import (
	"context"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// BenchmarkServeDNS measures end-to-end query handling against the demo
// dataset.
func BenchmarkServeDNS(b *testing.B) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Demo:          true,
			ClusterDomain: "cluster.local",
		},
	}
	k := New(cfg)

	queries := []struct {
		name  string
		qtype uint16
	}{
		{"kubernetes.default.svc.cluster.local.", dns.TypeA},
		{"kube-dns.kube-system.svc.cluster.local.", dns.TypeA},
		{"app-1.production.svc.cluster.local.", dns.TypeA},
		{"_https._tcp.kubernetes.default.svc.cluster.local.", dns.TypeSRV},
		{"10-244-1-10.default.pod.cluster.local.", dns.TypeA},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := queries[i%len(queries)]
		req := new(dns.Msg)
		req.SetQuestion(q.name, q.qtype)
		ch := &middleware.Chain{
			Writer:  &mockResponseWriter{},
			Request: middleware.NewRequest(req),
		}
		k.ServeDNS(context.Background(), ch)
	}
}

// BenchmarkRegistryResolveQuery measures registry lookup latency under
// concurrent reads. Service names are kept ASCII to keep query strings
// realistic.
func BenchmarkRegistryResolveQuery(b *testing.B) {
	registry := NewRegistry()

	for i := 0; i < 100; i++ {
		registry.AddService(&Service{
			Name:       fmt.Sprintf("svc-%d", i),
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, byte(i / 256), byte(i % 256)}},
			IPFamilies: []string{"IPv4"},
		})
	}

	queries := make([]string, 100)
	for i := 0; i < 100; i++ {
		queries[i] = fmt.Sprintf("svc-%d.default.svc.cluster.local.", i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			registry.ResolveQuery(queries[i%100], dns.TypeA)
			i++
		}
	})
}
