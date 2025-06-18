package kubernetes

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// BenchmarkKillerMode tests the KILLER MODE performance
func BenchmarkKillerMode(b *testing.B) {
	cfg := &config.Config{
		Plugins: map[string]config.Plugin{
			"kubernetes": {
				Config: map[string]interface{}{
					"killer_mode": true,
				},
			},
		},
	}

	k := New(cfg)

	// Common queries to benchmark
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

		w := &mockResponseWriter{}
		ch := &middleware.Chain{
			Writer:  w,
			Request: req,
		}

		k.ServeDNS(context.Background(), ch)
	}

	stats := k.Stats()
	b.Logf("Cache hit rate: %.2f%%", stats["hit_rate"])
	if predictor, ok := stats["predictor"].(map[string]interface{}); ok {
		b.Logf("ML predictions: %v", predictor["predictions"])
	}
	if cache, ok := stats["cache"].(map[string]interface{}); ok {
		b.Logf("Zero-alloc cache stats: %+v", cache)
	}
}

// BenchmarkBoringMode tests the standard mode
func BenchmarkBoringMode(b *testing.B) {
	cfg := &config.Config{
		Plugins: map[string]config.Plugin{
			"kubernetes": {
				Config: map[string]interface{}{
					"killer_mode": false,
				},
			},
		},
	}

	k := New(cfg)

	queries := []struct {
		name  string
		qtype uint16
	}{
		{"kubernetes.default.svc.cluster.local.", dns.TypeA},
		{"kube-dns.kube-system.svc.cluster.local.", dns.TypeA},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		q := queries[i%len(queries)]

		req := new(dns.Msg)
		req.SetQuestion(q.name, q.qtype)

		w := &mockResponseWriter{}
		ch := &middleware.Chain{
			Writer:  w,
			Request: req,
		}

		k.ServeDNS(context.Background(), ch)
	}

	stats := k.Stats()
	b.Logf("Cache hit rate: %.2f%%", stats["hit_rate"])
}

// BenchmarkHighPerformanceCache tests zero-allocation performance
func BenchmarkHighPerformanceCache(b *testing.B) {
	cache := NewZeroAllocCache()

	// Pre-populate cache
	for i := 0; i < 100; i++ {
		qname := "service" + string(rune('0'+i)) + ".default.svc.cluster.local."
		msg := new(dns.Msg)
		msg.SetQuestion(qname, dns.TypeA)
		msg.Response = true
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: []byte{10, 96, 0, byte(i)},
			},
		}
		cache.Store(qname, dns.TypeA, msg)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		qname := "service" + string(rune('0'+i%100)) + ".default.svc.cluster.local."
		cache.Get(qname, dns.TypeA, uint16(i))
	}

	stats := cache.Stats()
	b.Logf("Zero-alloc cache stats: %+v", stats)
}

// BenchmarkShardedRegistry tests lock-free registry performance
func BenchmarkShardedRegistry(b *testing.B) {
	registry := NewShardedRegistry()

	// Pre-populate services
	for i := 0; i < 1000; i++ {
		registry.AddService(&Service{
			Name:       "service" + string(rune('0'+i)),
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, byte(i / 256), byte(i % 256)}},
			IPFamilies: []string{"IPv4"},
		})
	}

	queries := make([]string, 100)
	for i := 0; i < 100; i++ {
		queries[i] = "service" + string(rune('0'+i)) + ".default.svc.cluster.local."
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

	stats := registry.GetStats()
	b.Logf("Sharded registry stats: %+v", stats)
}
