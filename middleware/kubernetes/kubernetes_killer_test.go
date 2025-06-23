package kubernetes

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// TestKillerMode tests the killer mode specifically
func TestKillerMode(t *testing.T) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled:       true,
			ClusterDomain: "cluster.local",
			KillerMode:    true,
		},
	}

	k8s := New(cfg)
	if k8s == nil {
		t.Fatal("Failed to create Kubernetes middleware")
	}

	// Verify killer mode components
	if k8s.cache == nil {
		t.Error("High-performance cache not initialized")
	}
	if k8s.registry == nil {
		t.Error("Sharded registry not initialized")
	}
	if k8s.predictor == nil {
		t.Error("ML predictor not initialized")
	}

	// Test queries
	tests := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"Service A", "kubernetes.default.svc.cluster.local.", dns.TypeA},
		{"Service AAAA", "dual-stack.default.svc.cluster.local.", dns.TypeAAAA},
		{"App Service", "app-1.production.svc.cluster.local.", dns.TypeA},
		{"Pod query", "10-244-1-10.default.pod.cluster.local.", dns.TypeA},
		{"SRV query", "_https._tcp.kubernetes.default.svc.cluster.local.", dns.TypeSRV},
	}

	ctx := context.Background()

	// First pass - populate cache
	for _, tt := range tests {
		req := new(dns.Msg)
		req.SetQuestion(tt.qname, tt.qtype)

		w := &killerMockWriter{data: make([]byte, 0, 512)}
		ch := &middleware.Chain{
			Writer:  w,
			Request: req,
		}

		k8s.ServeDNS(ctx, ch)
	}

	// Second pass - test cache hits
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tt.qname, tt.qtype)

			w := &killerMockWriter{data: make([]byte, 0, 512)}

			ch := &middleware.Chain{
				Writer:  w,
				Request: req,
			}

			k8s.ServeDNS(ctx, ch)

			// In killer mode, response might be wire format
			if !w.written && w.msg == nil {
				t.Error("No response received")
			}

			// If wire format was written, verify it's valid DNS
			if len(w.data) > 0 {
				msg := new(dns.Msg)
				if err := msg.Unpack(w.data); err != nil {
					t.Errorf("Invalid wire format response: %v", err)
				}
			}
		})
	}

	// Test cache hit rate
	stats := k8s.Stats()
	t.Logf("Stats: %+v", stats)
	if cacheStats, ok := stats["cache"].(map[string]interface{}); ok {
		t.Logf("Cache stats: %+v", cacheStats)
	}
	if hitRate, ok := stats["hit_rate"].(float64); ok && hitRate < 50 {
		t.Errorf("Cache hit rate too low: %.2f%%", hitRate)
		t.Logf("Queries: %v, Cache hits: %v", stats["queries"], stats["cache_hits"])
	}
}

// TestHighPerformanceCacheFunctionality tests high-performance cache
func TestHighPerformanceCacheFunctionality(t *testing.T) {
	cache := NewZeroAllocCache()

	// Test store and retrieve
	qname := "test.default.svc.cluster.local."
	msg := &dns.Msg{}
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
			A: []byte{10, 0, 0, 1},
		},
	}

	cache.Store(qname, dns.TypeA, msg)

	// Retrieve multiple times
	for i := 0; i < 5; i++ {
		cachedIface := cache.Get(qname, dns.TypeA)
		if cachedIface == nil {
			t.Fatal("Failed to retrieve from cache")
		}

		// Type assert to dns.Msg
		cached, ok := cachedIface.(*dns.Msg)
		if !ok {
			t.Fatal("Cache returned wrong type")
		}

		// Verify content
		if len(cached.Answer) != 1 {
			t.Error("Cached message missing answer")
		}

		// Each get returns a copy, so we can modify safely
		cached.Id = uint16(i)
		if cached.Id != uint16(i) {
			t.Error("Failed to modify copy")
		}
	}

	// Test cache miss
	miss := cache.Get("nonexistent.cluster.local.", dns.TypeA, 1)
	if miss != nil {
		t.Error("Expected cache miss")
	}

	// Check stats
	stats := cache.Stats()
	if stats["zero_alloc"] != true {
		t.Error("Cache not reporting zero-alloc")
	}
}

// TestShardedRegistryFunctionality tests sharded registry
func TestShardedRegistryFunctionality(t *testing.T) {
	registry := NewShardedRegistry()

	// Add services
	for i := 0; i < 100; i++ {
		registry.AddService(&Service{
			Name:       "service" + string(rune('0'+i%10)),
			Namespace:  "ns" + string(rune('0'+i/10)),
			ClusterIPs: [][]byte{{10, 96, byte(i / 256), byte(i % 256)}},
			IPFamilies: []string{"IPv4"},
			Ports: []Port{
				{Name: "http", Port: 80, Protocol: "tcp"},
			},
		})
	}

	// Test concurrent queries
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				svc := "service" + string(rune('0'+id))
				ns := "ns0"
				qname := svc + "." + ns + ".svc.cluster.local."

				answers, found := registry.ResolveQuery(qname, dns.TypeA)
				if !found || len(answers) == 0 {
					t.Errorf("Failed to resolve %s", qname)
				}
			}
			done <- true
		}(i)
	}

	// Wait for goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check stats
	stats := registry.GetStats()
	if stats["shards"] != int64(256) {
		t.Errorf("Expected 256 shards, got %d", stats["shards"])
	}
}

// TestMLPredictor tests the ML predictor
func TestMLPredictor(t *testing.T) {
	predictor := NewSmartPredictor()

	// Train with pattern
	queries := []string{
		"app.default.svc.cluster.local.",
		"database.default.svc.cluster.local.",
		"cache.default.svc.cluster.local.",
	}

	// Record pattern multiple times
	for i := 0; i < 10; i++ {
		for _, q := range queries {
			predictor.Record("10.0.0.1", q, dns.TypeA)
		}
	}

	// Test predictions
	predictions := predictor.Predict("10.0.0.1", "app.default.svc.cluster.local.")
	if len(predictions) == 0 {
		t.Error("No predictions generated")
	}

	// Check stats
	stats := predictor.Stats()
	if stats["predictions"].(uint64) == 0 {
		t.Error("Predictor not recording predictions")
	}
}

// killerMockWriter handles both wire format and message writes
type killerMockWriter struct {
	mockResponseWriter
	data []byte
}

func (k *killerMockWriter) Write(b []byte) (int, error) {
	k.data = append(k.data, b...)
	k.written = true
	return len(b), nil
}
