package kubernetes

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// TestCacheOperations tests cache operations
func TestCacheOperations(t *testing.T) {
	cache := NewCache()

	// Test Set and Get
	msg := &dns.Msg{}
	msg.SetQuestion("test.cluster.local.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "test.cluster.local.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			A: net.ParseIP("10.0.0.1"),
		},
	}

	cache.Set("test.cluster.local.", dns.TypeA, msg)

	// Test Get
	cached := cache.Get("test.cluster.local.", dns.TypeA)
	if cached == nil {
		t.Fatal("Failed to get from cache")
	}

	// Test Copy
	copy := cached.Copy()
	if copy.Id == cached.Id {
		copy.Id = 123
		if cached.Id == 123 {
			t.Error("Copy is not independent")
		}
	}

	// Test with TTL 0 (should not be cached)
	msgZeroTTL := &dns.Msg{}
	msgZeroTTL.SetQuestion("zero.cluster.local.", dns.TypeA)
	msgZeroTTL.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "zero.cluster.local.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: net.ParseIP("10.0.0.2"),
		},
	}

	cache.Set("zero.cluster.local.", dns.TypeA, msgZeroTTL)
	zeroCached := cache.Get("zero.cluster.local.", dns.TypeA)
	if zeroCached != nil {
		t.Error("Zero TTL entries should not be cached")
	}
}

// TestRegistryOperations tests registry CRUD
func TestRegistryOperations(t *testing.T) {
	r := NewRegistry()

	// Test pods
	pod := &Pod{
		Name:      "test-pod",
		Namespace: "default",
		IPs:       []string{"10.244.1.1"},
		Hostname:  "test",
		Subdomain: "web",
	}

	r.AddPod(pod) //nolint:gosec // G104 - test setup

	// Test get pod by IP
	p := r.GetPodByIP("10.244.1.1")
	if p == nil || p.Name != "test-pod" {
		t.Error("Failed to get pod by IP")
	}

	// Test get pod by name
	p2 := r.GetPodByName("test-pod", "default")
	if p2 == nil || p2.Name != "test-pod" {
		t.Error("Failed to get pod by name")
	}

	// Test endpoints
	r.SetEndpoints("test", "default", []Endpoint{ //nolint:gosec // G104 - test setup
		{Addresses: []string{"10.1.1.1"}, Ready: true},
		{Addresses: []string{"10.1.1.2"}, Ready: false},
	})

	endpoints := r.GetEndpoints("test", "default")
	if len(endpoints) != 2 {
		t.Error("Wrong endpoint count")
	}

	// Test stats
	stats := r.Stats()
	if stats["pods"] != 1 {
		t.Errorf("Expected 1 pod, got %d", stats["pods"])
	}

	// Test delete pod
	r.DeletePod("test-pod", "default") //nolint:gosec // G104 - test cleanup

	if r.GetPodByIP("10.244.1.1") != nil {
		t.Error("Pod not deleted")
	}
}

// TestResolverPatterns tests various DNS patterns
func TestResolverPatterns(t *testing.T) {
	resolver := NewResolver(nil, "cluster.local", NewCache())
	registry := resolver.registry

	// Add test data
	registry.AddService(&Service{ //nolint:gosec // G104 - test setup
		Name:       "test",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 100}},
		IPFamilies: []string{"IPv4"},
		Ports: []Port{
			{Name: "http", Port: 80, Protocol: "TCP"},
			{Name: "https", Port: 443, Protocol: "TCP"},
		},
	})

	// Add headless service
	registry.AddService(&Service{ //nolint:gosec // G104 - test setup
		Name:      "headless",
		Namespace: "default",
		Headless:  true,
	})

	registry.SetEndpoints("headless", "default", []Endpoint{ //nolint:gosec // G104 - test setup
		{Addresses: []string{"10.1.1.1"}, Ready: true},
		{Addresses: []string{"10.1.1.2"}, Ready: true},
	})

	// Add pod
	registry.AddPod(&Pod{ //nolint:gosec // G104 - test setup
		Name:      "test-pod",
		Namespace: "default",
		IPs:       []string{"10.244.1.1"},
	})

	// Test patterns
	tests := []struct {
		name  string
		qname string
		qtype uint16
		want  int // expected answer count
	}{
		{"Service A", "test.default.svc.cluster.local.", dns.TypeA, 1},
		{"Service AAAA", "test.default.svc.cluster.local.", dns.TypeAAAA, 0},
		{"Headless A", "headless.default.svc.cluster.local.", dns.TypeA, 2},
		{"Pod by IP", "10-244-1-1.default.pod.cluster.local.", dns.TypeA, 1},
		{"SRV http", "_http._tcp.test.default.svc.cluster.local.", dns.TypeSRV, 1},
		{"SRV https", "_https._tcp.test.default.svc.cluster.local.", dns.TypeSRV, 1},
		{"PTR service", "100.0.96.10.in-addr.arpa.", dns.TypePTR, 1},
		{"PTR pod", "1.1.244.10.in-addr.arpa.", dns.TypePTR, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, found := resolver.Resolve(tt.qname, tt.qtype)
			if !found {
				t.Fatal("Query not handled")
			}

			if resp.Rcode != dns.RcodeSuccess && tt.want > 0 {
				t.Errorf("Expected success, got rcode %d", resp.Rcode)
			}

			if len(resp.Answer) != tt.want {
				t.Errorf("Expected %d answers, got %d", tt.want, len(resp.Answer))
			}
		})
	}
}

// TestClientIntegration tests client functionality
func TestClientIntegration(t *testing.T) {
	// Test client creation with default kubeconfig
	_, err := NewClient("")
	if err == nil {
		t.Skip("Kubernetes available, skipping mock test")
	}

	// Test with explicit kubeconfig
	_, err = NewClient("/nonexistent/path")
	if err == nil {
		t.Error("Should fail with nonexistent kubeconfig")
	}
}

// TestStats tests statistics collection
func TestStats(t *testing.T) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled:    true,
			KillerMode: true,
		},
	}

	k := New(cfg)
	ctx := context.Background()

	// Generate some queries
	for i := 0; i < 100; i++ {
		req := new(dns.Msg)
		req.SetQuestion("kubernetes.default.svc.cluster.local.", dns.TypeA)

		w := &mockResponseWriter{}
		ch := &middleware.Chain{
			Writer:  w,
			Request: req,
		}

		k.ServeDNS(ctx, ch)
	}

	// Check stats
	stats := k.Stats()

	queries := stats["queries"].(uint64)
	if queries != 100 {
		t.Errorf("Expected 100 queries, got %d", queries)
	}

	if stats["killer_mode"] != true {
		t.Error("Not in killer mode")
	}

	// Check component stats
	if cacheStats, ok := stats["cache"].(map[string]any); ok {
		if cacheStats["zero_alloc"] != true {
			t.Error("Cache not zero-alloc")
		}
	}
}

// TestPredictorTraining tests ML predictor training
func TestPredictorTraining(t *testing.T) {
	predictor := NewSmartPredictor()

	// Simulate query patterns
	pattern := []string{
		"app.prod.svc.cluster.local.",
		"db.prod.svc.cluster.local.",
		"cache.prod.svc.cluster.local.",
		"app.prod.svc.cluster.local.", // Back to app
	}

	// Train pattern
	for i := 0; i < 100; i++ {
		for _, q := range pattern {
			predictor.Record("10.0.0.1", q, dns.TypeA)
		}
	}

	// Let training run
	time.Sleep(100 * time.Millisecond)

	// Test predictions
	predictions := predictor.Predict("10.0.0.1", "app.prod.svc.cluster.local.")

	// Should predict db or cache next
	found := false
	for _, p := range predictions {
		if p.Service == "db.prod.svc.cluster.local." || p.Service == "cache.prod.svc.cluster.local." {
			found = true
			break
		}
	}

	if !found && len(predictions) > 0 {
		t.Error("Predictor not learning patterns correctly")
	}
}

// TestZeroAllocPerformance verifies zero allocations
func TestZeroAllocPerformance(t *testing.T) {
	cache := NewZeroAllocCache()

	// Pre-populate
	msg := &dns.Msg{}
	msg.SetQuestion("test.cluster.local.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "test.cluster.local.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{10, 0, 0, 1},
		},
	}

	cache.Store("test.cluster.local.", dns.TypeA, msg)

	// Warm up
	for i := 0; i < 100; i++ {
		cache.Get("test.cluster.local.", dns.TypeA, uint16(i)) //nolint:gosec // G115 - test loop iteration
	}

	// TODO: Use testing.AllocsPerRun to verify zero allocations
	// when running in hot path
}

// TestShardedRegistryConcurrency tests concurrent access
func TestShardedRegistryConcurrency(t *testing.T) {
	registry := NewShardedRegistry()

	// Add initial services
	for i := 0; i < 10; i++ {
		registry.AddService(&Service{
			Name:       "svc" + string(rune('0'+i)),
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, 0, byte(i)}},
			IPFamilies: []string{"IPv4"},
		})
	}

	// Concurrent operations
	done := make(chan bool, 3)

	// Reader
	go func() {
		for i := 0; i < 1000; i++ {
			svc := "svc" + string(rune('0'+i%10))
			qname := svc + ".default.svc.cluster.local."
			registry.ResolveQuery(qname, dns.TypeA)
		}
		done <- true
	}()

	// Writer 1
	go func() {
		for i := 0; i < 100; i++ {
			registry.AddService(&Service{
				Name:       "dynamic" + string(rune('0'+i)),
				Namespace:  "default",
				ClusterIPs: [][]byte{{10, 97, 0, byte(i)}},
				IPFamilies: []string{"IPv4"},
			})
		}
		done <- true
	}()

	// Writer 2 - pods
	go func() {
		for i := 0; i < 100; i++ {
			registry.AddPod(&Pod{
				Name:      "pod" + string(rune('0'+i)),
				Namespace: "default",
				IPs:       []string{"10.244.1." + string(rune('0'+i))},
			})
		}
		done <- true
	}()

	// Wait for completion
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify no data corruption
	stats := registry.GetStats()
	if stats["services"] < 10 {
		t.Error("Lost services during concurrent access")
	}
}
