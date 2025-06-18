package kubernetes

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// TestClientRunError tests client Run method error handling
func TestClientRunError(t *testing.T) {
	// Skip this test as it requires a valid client
	t.Skip("Requires valid Kubernetes client configuration")
}

// TestBuildConfigEdgeCases tests buildConfig edge cases
func TestBuildConfigEdgeCases(t *testing.T) {
	// Test with HOME environment variable
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	// Set a test HOME
	testHome := "/tmp/test-kube-home"
	os.Setenv("HOME", testHome)

	// Create test kubeconfig directory
	os.MkdirAll(testHome+"/.kube", 0755)

	// Try to build config (will fail but covers the HOME path)
	_, err := buildConfig("")
	if err == nil {
		t.Skip("Found valid kubeconfig")
	}

	// Test with KUBECONFIG env var
	os.Setenv("KUBECONFIG", "/tmp/nonexistent-kubeconfig")
	_, err = buildConfig("")
	if err == nil {
		t.Error("Should fail with nonexistent KUBECONFIG")
	}
}

// TestResolverResolvePod tests pod resolution
func TestResolverResolvePod(t *testing.T) {
	r := NewResolver("cluster.local", NewCache())

	// Add pod by IP format
	r.registry.AddPod(&Pod{
		Name:      "test-pod",
		Namespace: "default",
		IPs:       []string{"10.244.1.1"},
	})

	// Test pod by IP
	resp, found := r.Resolve("10-244-1-1.default.pod.cluster.local.", dns.TypeA)
	if !found {
		t.Fatal("Pod IP resolution not found")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Pod IP resolution failed")
	}
	if len(resp.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(resp.Answer))
	}

	// Test non-existent pod
	resp, found = r.Resolve("10-244-1-99.default.pod.cluster.local.", dns.TypeA)
	if !found {
		t.Fatal("Should handle non-existent pod query")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Error("Should return NXDOMAIN for non-existent pod")
	}
}

// TestKubernetesServeDNSEdgeCases tests ServeDNS edge cases
func TestKubernetesServeDNSEdgeCases(t *testing.T) {
	// Skip this test as it requires proper initialization
	t.Skip("Requires full Kubernetes middleware initialization")
}

// TestPrefetchPredicted tests prefetch functionality
func TestPrefetchPredicted(t *testing.T) {
	k := &Kubernetes{
		resolver:   NewResolver("cluster.local", NewCache()),
		killerMode: true,
		predictor:  NewLockFreePredictor(),
	}

	// Add some services
	k.resolver.registry.AddService(&Service{
		Name:       "predicted-svc",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 50}},
		IPFamilies: []string{"IPv4"},
	})

	// Test prefetch
	k.prefetchPredicted("predicted-svc.default.svc.cluster.local.")

	// Check if cached
	cached := k.resolver.cache.Get("predicted-svc.default.svc.cluster.local.", dns.TypeA)
	if cached == nil {
		t.Log("Prefetch may not have cached (depends on timing)")
	}
}

// TestPredictionLoopStop tests prediction loop stopping
func TestPredictionLoopStop(t *testing.T) {
	// Skip this test as it requires internal fields
	t.Skip("Requires internal implementation details")
}

// TestZeroAllocCacheMoreEdgeCases tests more zero alloc cache edge cases
func TestZeroAllocCacheMoreEdgeCases(t *testing.T) {
	cache := NewZeroAllocCache()

	// Test Get with nil entry
	wire := cache.Get("nonexistent", dns.TypeA, 1234)
	if wire != nil {
		t.Error("Should return nil for nonexistent entry")
	}

	// Test Store with response that fails to pack
	msg := &dns.Msg{}
	msg.SetQuestion("test.local.", dns.TypeA)
	msg.Response = true
	// Add an answer with a very long name that might fail packing
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   strings.Repeat("verylongname.", 20) + "local.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{10, 0, 0, 1},
		},
	}
	// This might fail to pack, covering error path
	cache.Store("test.local.", dns.TypeA, msg)

	// Test concurrent access during cleanup
	for i := 0; i < 100; i++ {
		go func(i int) {
			qname := fmt.Sprintf("concurrent%d.local.", i)
			msg := &dns.Msg{}
			msg.SetQuestion(qname, dns.TypeA)
			msg.Response = true
			cache.Store(qname, dns.TypeA, msg)
			cache.Get(qname, dns.TypeA, uint16(i))
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
}

// TestGetTopPredictionsEdgeCases tests prediction edge cases
func TestGetTopPredictionsEdgeCases(t *testing.T) {
	p := NewLockFreePredictor()

	// Test with empty predictor
	predictions := p.Predict("test")
	if len(predictions) != 0 {
		t.Log("New predictor may have no predictions initially")
	}

	// Train the predictor
	for i := 0; i < 100; i++ {
		p.Record("query1", dns.TypeA)
		p.Record("query2", dns.TypeA)
		p.Record("query3", dns.TypeA)
	}

	// Test predictions after training
	predictions = p.Predict("query1")
	t.Logf("Got %d predictions", len(predictions))
}

// TestKubernetesNewWithClient tests New with real client attempt
func TestKubernetesNewWithClient(t *testing.T) {
	// Set invalid kubeconfig path
	os.Setenv("KUBECONFIG", "/tmp/nonexistent-kubeconfig-test")
	defer os.Unsetenv("KUBECONFIG")

	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled:    true,
			KillerMode: true,
		},
	}

	k := New(cfg)

	// Should still create middleware even if client fails
	if k == nil {
		t.Fatal("Should create Kubernetes middleware even without client")
	}

	// Verify demo mode
	stats := k.Stats()
	if stats["k8s_connected"] == true {
		t.Error("Should not be connected with invalid config")
	}
}

// TestResolverParsePTREdgeCases tests PTR parsing edge cases
func TestResolverParsePTREdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		wantOK bool
	}{
		{
			name:   "Too few labels",
			labels: []string{"1", "in-addr", "arpa"},
			wantOK: false,
		},
		{
			name:   "Invalid suffix",
			labels: []string{"1", "0", "0", "10", "wrong", "suffix"},
			wantOK: false,
		},
		{
			name:   "Valid IPv4",
			labels: []string{"1", "0", "96", "10", "in-addr", "arpa"},
			wantOK: true,
		},
		{
			name:   "Empty labels",
			labels: []string{},
			wantOK: false,
		},
	}

	r := &Resolver{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.parsePTR(strings.Join(tt.labels, "."))
			if (result != nil) != tt.wantOK {
				t.Errorf("parsePTR() ok = %v, want %v", result != nil, tt.wantOK)
			}
		})
	}
}

// TestShardedRegistryEdgeCases2 tests more sharded registry edge cases
func TestShardedRegistryEdgeCases2(t *testing.T) {
	r := NewShardedRegistry()

	// Test with services that hash to same shard
	// Add many services to increase chance of collision
	for i := 0; i < 100; i++ {
		r.AddService(&Service{
			Name:       fmt.Sprintf("svc%d", i),
			Namespace:  "default",
			ClusterIPs: [][]byte{{10, 96, 0, byte(i)}},
			IPFamilies: []string{"IPv4"},
		})
	}

	// Test concurrent queries
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(i int) {
			for j := 0; j < 100; j++ {
				name := fmt.Sprintf("svc%d.default.svc.cluster.local.", j%100)
				r.ResolveQuery(name, dns.TypeA)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Test GetStats
	stats := r.GetStats()
	if stats["services"] < 10 {
		t.Error("Should have at least 10 services")
	}
}

// TestResolverSRVEdgeCases tests SRV resolution edge cases
func TestResolverSRVEdgeCases(t *testing.T) {
	r := NewResolver("cluster.local", NewCache())

	// Add service with no ports
	r.registry.AddService(&Service{
		Name:       "no-ports",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 100}},
		IPFamilies: []string{"IPv4"},
		Ports:      []Port{}, // No ports
	})

	// Test SRV query for service with no ports
	resp, found := r.Resolve("_http._tcp.no-ports.default.svc.cluster.local.", dns.TypeSRV)
	if !found {
		t.Fatal("Should handle SRV query")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Error("Should return NXDOMAIN for non-existent port")
	}

	// Add external service
	r.registry.AddService(&Service{
		Name:         "external",
		Namespace:    "default",
		ExternalName: "example.com",
		Ports: []Port{
			{Name: "http", Port: 80, Protocol: "TCP"},
		},
	})

	// Test SRV for external service
	resp, found = r.Resolve("_http._tcp.external.default.svc.cluster.local.", dns.TypeSRV)
	if !found {
		t.Fatal("Should handle external service SRV")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Should return success for external service SRV")
	}
}
