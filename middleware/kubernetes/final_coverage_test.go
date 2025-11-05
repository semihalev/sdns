package kubernetes

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// TestPredictionLoop tests the prediction loop functionality
func TestPredictionLoop(t *testing.T) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled:    true,
			KillerMode: true,
		},
	}

	k := New(cfg)

	// Generate queries to train predictor
	ctx := context.Background()
	queries := []string{
		"app.default.svc.cluster.local.",
		"db.default.svc.cluster.local.",
		"cache.default.svc.cluster.local.",
	}

	// Train pattern
	for i := 0; i < 10; i++ {
		for _, q := range queries {
			req := new(dns.Msg)
			req.SetQuestion(q, dns.TypeA)

			w := &mockResponseWriter{}
			ch := &middleware.Chain{
				Writer:  w,
				Request: req,
			}

			k.ServeDNS(ctx, ch)
		}
	}

	// Test prefetch with new method
	k.prefetchPredictedWithClient("10.0.0.1", "app.default.svc.cluster.local.", dns.TypeA)

	// Check stats to ensure prediction is working
	stats := k.Stats()
	if predictor, ok := stats["predictor"].(map[string]any); ok {
		if predictions, ok := predictor["predictions"].(uint64); ok && predictions == 0 {
			t.Error("Predictor not generating predictions")
		}
	}
}

// TestRegistryMethods tests all registry methods
func TestRegistryMethods(t *testing.T) {
	r := NewRegistry()

	// Test GetServiceByIP
	svc := &Service{
		Name:       "test-ip",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 50}},
	}
	r.AddService(svc) //nolint:gosec // G104 - test setup

	found := r.GetServiceByIP([]byte{10, 96, 0, 50})
	if found == nil || found.Name != "test-ip" {
		t.Error("GetServiceByIP failed")
	}

	// Test not found
	notFound := r.GetServiceByIP([]byte{10, 96, 0, 99})
	if notFound != nil {
		t.Error("Should return nil for non-existent IP")
	}

	// Test Stats instead
	stats := r.Stats()
	if stats["services"] == 0 {
		t.Error("No services in registry")
	}

	// Test GetEndpoints with non-existent
	endpoints := r.GetEndpoints("nonexistent", "default")
	if len(endpoints) != 0 {
		t.Error("Should return empty endpoints for non-existent service")
	}
}

// TestResolverHelpers tests resolver helper methods
func TestResolverHelpers(t *testing.T) {
	r := NewResolver(nil, "cluster.local", NewCache())

	// Add test data
	r.registry.AddService(&Service{ //nolint:gosec // G104 - test setup
		Name:       "stateful",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 60}},
		IPFamilies: []string{"IPv4"},
		Headless:   true,
	})

	r.registry.SetEndpoints("stateful", "default", []Endpoint{ //nolint:gosec // G104 - test setup
		{Addresses: []string{"10.1.1.1"}, Hostname: "stateful-0", Ready: true},
		{Addresses: []string{"10.1.1.2"}, Hostname: "stateful-1", Ready: true},
	})

	// Test regular headless service query (returns all endpoints)
	resp, found := r.Resolve("stateful.default.svc.cluster.local.", dns.TypeA)
	if !found {
		t.Fatal("Headless service query not handled")
	}

	if len(resp.Answer) != 2 {
		t.Errorf("Headless service should return all endpoints, got %d answers", len(resp.Answer))
	}

	// Test AAAA for IPv4-only service
	resp, found = r.Resolve("stateful.default.svc.cluster.local.", dns.TypeAAAA)
	if !found || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Error("AAAA query should return empty answer for IPv4-only service")
	}
}

// TestCacheCopy tests cache message copying
func TestCacheCopy(t *testing.T) {
	cache := NewCache()

	// Create and cache a message
	original := &dns.Msg{}
	original.SetQuestion("test.local.", dns.TypeA)
	original.Id = 100
	original.Response = true
	original.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "test.local.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			A: []byte{10, 0, 0, 1},
		},
	}

	cache.Set("test.local.", dns.TypeA, original)

	// Get and verify copy
	cached := cache.Get("test.local.", dns.TypeA)
	if cached == nil {
		t.Fatal("Failed to get from cache")
	}

	// Verify it's a copy
	copy := cached.Copy()
	copy.Id = 200

	if cached.Id == 200 {
		t.Error("Copy modified original cached message")
	}

	// Modify copy's answer
	if len(copy.Answer) > 0 {
		copy.Answer[0].(*dns.A).A = []byte{10, 0, 0, 2}

		// Original should be unchanged
		if a, ok := cached.Answer[0].(*dns.A); ok {
			if a.A[3] != 1 {
				t.Error("Copy modified original answer")
			}
		}
	}
}

// TestShardedRegistryHelpers tests sharded registry helper methods
func TestShardedRegistryHelpers(t *testing.T) {
	r := NewShardedRegistry()

	// Test with IPv6-like pod IP (though stored as string)
	pod := &Pod{
		Name:      "ipv6-pod",
		Namespace: "default",
		IPs:       []string{"2001:db8::1"},
	}
	r.AddPod(pod)

	// Test malformed pod query
	_, found := r.ResolveQuery("not-ip.default.pod.cluster.local.", dns.TypeA)
	if found {
		t.Error("Should not resolve malformed pod IP")
	}

	// Test service without ClusterIP
	r.AddService(&Service{
		Name:      "headless",
		Namespace: "default",
		Headless:  true,
	})

	answers, found := r.ResolveQuery("headless.default.svc.cluster.local.", dns.TypeA)
	if !found || len(answers) != 0 {
		t.Error("Headless service without endpoints should return empty")
	}
}

// TestPortMatching tests port name matching
func TestPortMatching(t *testing.T) {
	r := NewShardedRegistry()

	// Add service with mixed case protocols
	r.AddService(&Service{
		Name:       "mixed",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 70}},
		Ports: []Port{
			{Name: "http", Port: 80, Protocol: "TCP"},
			{Name: "dns", Port: 53, Protocol: "udp"},
		},
	})

	// Test case-insensitive protocol matching
	srv, found := r.ResolveQuery("_http._tcp.mixed.default.svc.cluster.local.", dns.TypeSRV)
	if !found || len(srv) != 1 {
		t.Error("Failed to match TCP port case-insensitively")
	}

	srv, found = r.ResolveQuery("_dns._UDP.mixed.default.svc.cluster.local.", dns.TypeSRV)
	if !found || len(srv) != 1 {
		t.Error("Failed to match UDP port case-insensitively")
	}
}

// TestObjectRef tests ObjectRef type
func TestObjectRef(t *testing.T) {
	ref := &ObjectRef{
		Kind:      "Pod",
		Name:      "test-pod",
		Namespace: "default",
	}

	if ref.Kind != "Pod" {
		t.Error("ObjectRef Kind not set")
	}

	// Test in endpoint
	ep := &Endpoint{
		Addresses: []string{"10.1.1.1"},
		Ready:     true,
		TargetRef: ref,
	}

	if ep.TargetRef.Name != "test-pod" {
		t.Error("TargetRef not accessible")
	}
}

// TestPodFields tests Pod type fields
func TestPodFields(t *testing.T) {
	pod := &Pod{
		Name:      "test-pod",
		Namespace: "default",
		IPs:       []string{"10.244.1.1"},
		Hostname:  "test-host",
		Subdomain: "test-sub",
	}

	if pod.Hostname != "test-host" {
		t.Error("Pod hostname not set")
	}

	if pod.Subdomain != "test-sub" {
		t.Error("Pod subdomain not set")
	}
}
