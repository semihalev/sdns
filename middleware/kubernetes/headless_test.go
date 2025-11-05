package kubernetes

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// TestHeadlessServiceEndpoints tests headless service endpoint resolution
func TestHeadlessServiceEndpoints(t *testing.T) {
	// Test killer mode (uses sharded registry)
	t.Run("killer_mode", func(t *testing.T) {
		cfg := &config.Config{
			Kubernetes: config.KubernetesConfig{
				Enabled:    true,
				KillerMode: true,
			},
		}

		k := New(cfg)

		// Add a headless service
		k.registry.AddService(&Service{
			Name:      "myapp",
			Namespace: "default",
			Headless:  true,
		})

		// Add endpoints for the headless service
		k.registry.SetEndpoints("myapp", "default", []Endpoint{
			{Addresses: []string{"10.1.1.1", "2001:db8::1"}, Ready: true},
			{Addresses: []string{"10.1.1.2"}, Ready: true},
			{Addresses: []string{"10.1.1.3"}, Ready: false}, // Not ready, should be skipped
		})

		// Test A record query
		ctx := context.Background()
		req := new(dns.Msg)
		req.SetQuestion("myapp.default.svc.cluster.local.", dns.TypeA)

		w := &mockResponseWriter{}
		ch := &middleware.Chain{
			Writer:  w,
			Request: req,
		}

		k.ServeDNS(ctx, ch)

		// Check response
		if !w.written {
			t.Fatal("No response written")
		}

		resp := w.msg

		// Should have 2 A records (not the not-ready one)
		if len(resp.Answer) != 2 {
			t.Errorf("Expected 2 A records, got %d", len(resp.Answer))
		}

		// Verify IPs
		ips := make(map[string]bool)
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips[a.A.String()] = true
			}
		}

		if !ips["10.1.1.1"] || !ips["10.1.1.2"] {
			t.Error("Missing expected IP addresses")
		}

		// Test AAAA record query
		req.SetQuestion("myapp.default.svc.cluster.local.", dns.TypeAAAA)
		w = &mockResponseWriter{}
		ch.Writer = w

		k.ServeDNS(ctx, ch)

		// Check response
		if !w.written {
			t.Fatal("No AAAA response written")
		}

		resp = w.msg

		// Should have 1 AAAA record
		if len(resp.Answer) != 1 {
			t.Errorf("Expected 1 AAAA record, got %d", len(resp.Answer))
		}

		if aaaa, ok := resp.Answer[0].(*dns.AAAA); ok {
			if aaaa.AAAA.String() != "2001:db8::1" {
				t.Errorf("Unexpected IPv6 address: %s", aaaa.AAAA.String())
			}
		}
	})

	// Test boring mode (uses standard registry)
	t.Run("boring_mode", func(t *testing.T) {
		cfg := &config.Config{
			Kubernetes: config.KubernetesConfig{
				Enabled:    true,
				KillerMode: false,
			},
		}

		k := New(cfg)

		// Add a headless service
		k.resolver.registry.AddService(&Service{ //nolint:gosec // G104 - test setup
			Name:      "myapp",
			Namespace: "default",
			Headless:  true,
		})

		// Add endpoints
		k.resolver.registry.SetEndpoints("myapp", "default", []Endpoint{ //nolint:gosec // G104 - test setup
			{Addresses: []string{"10.2.2.1"}, Ready: true},
			{Addresses: []string{"10.2.2.2"}, Ready: true},
		})

		// Test query
		ctx := context.Background()
		req := new(dns.Msg)
		req.SetQuestion("myapp.default.svc.cluster.local.", dns.TypeA)

		w := &mockResponseWriter{}
		ch := &middleware.Chain{
			Writer:  w,
			Request: req,
		}

		k.ServeDNS(ctx, ch)

		// Check response
		if !w.written || w.msg == nil || len(w.msg.Answer) != 2 {
			t.Errorf("Expected 2 A records for headless service in boring mode")
		}
	})
}

// TestHeadlessServiceNoEndpoints tests headless service with no endpoints
func TestHeadlessServiceNoEndpoints(t *testing.T) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled:    true,
			KillerMode: true,
		},
	}

	k := New(cfg)

	// Add a headless service with no endpoints
	k.registry.AddService(&Service{
		Name:      "empty",
		Namespace: "default",
		Headless:  true,
	})

	// Test query
	ctx := context.Background()
	req := new(dns.Msg)
	req.SetQuestion("empty.default.svc.cluster.local.", dns.TypeA)

	w := &mockResponseWriter{}
	ch := &middleware.Chain{
		Writer:  w,
		Request: req,
	}

	k.ServeDNS(ctx, ch)

	// Should get a response with no answers
	if !w.written {
		t.Fatal("No response written")
	}

	resp := w.msg

	if len(resp.Answer) != 0 {
		t.Errorf("Expected 0 answers for headless service with no endpoints, got %d", len(resp.Answer))
	}
}

// TestEndpointOperations tests endpoint add/remove operations
func TestEndpointOperations(t *testing.T) {
	r := NewShardedRegistry()

	// Test SetEndpoints
	r.SetEndpoints("test", "default", []Endpoint{
		{Addresses: []string{"10.1.1.1"}, Ready: true},
	})

	endpoints := r.GetEndpoints("test", "default")
	if len(endpoints) != 1 {
		t.Errorf("Expected 1 endpoint, got %d", len(endpoints))
	}

	// Test update endpoints
	r.SetEndpoints("test", "default", []Endpoint{
		{Addresses: []string{"10.1.1.1"}, Ready: true},
		{Addresses: []string{"10.1.1.2"}, Ready: true},
	})

	endpoints = r.GetEndpoints("test", "default")
	if len(endpoints) != 2 {
		t.Errorf("Expected 2 endpoints after update, got %d", len(endpoints))
	}

	// Test remove endpoints
	r.SetEndpoints("test", "default", []Endpoint{})

	endpoints = r.GetEndpoints("test", "default")
	if len(endpoints) != 0 {
		t.Errorf("Expected 0 endpoints after removal, got %d", len(endpoints))
	}

	// Test get non-existent endpoints
	endpoints = r.GetEndpoints("nonexistent", "default")
	if len(endpoints) != 0 {
		t.Errorf("Expected 0 endpoints for non-existent service, got %d", len(endpoints))
	}
}

// TestShardedRegistryStats tests that stats include endpoint sets
func TestShardedRegistryStats(t *testing.T) {
	r := NewShardedRegistry()

	// Add some data
	r.AddService(&Service{
		Name:       "test",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 1}},
	})

	r.SetEndpoints("test", "default", []Endpoint{
		{Addresses: []string{"10.1.1.1"}, Ready: true},
	})

	r.SetEndpoints("other", "default", []Endpoint{
		{Addresses: []string{"10.1.1.2"}, Ready: true},
	})

	stats := r.GetStats()

	if stats["endpoint_sets"] < 2 {
		t.Errorf("Expected at least 2 endpoint sets in stats, got %d", stats["endpoint_sets"])
	}
}
