package kubernetes

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// TestKubernetesMiddleware tests the Kubernetes middleware
func TestKubernetesMiddleware(t *testing.T) {
	testModes := []struct {
		name       string
		killerMode bool
	}{
		{"killer_mode", true},
		{"boring_mode", false},
	}

	for _, mode := range testModes {
		t.Run(mode.name, func(t *testing.T) {
			cfg := &config.Config{
				Kubernetes: config.KubernetesConfig{
					Enabled:       true,
					ClusterDomain: "cluster.local",
					KillerMode:    mode.killerMode,
				},
			}

			k8s := New(cfg)
			if k8s == nil {
				t.Fatal("Failed to create Kubernetes middleware")
			}

			// Test middleware name
			if k8s.Name() != "kubernetes" {
				t.Errorf("Expected name 'kubernetes', got %s", k8s.Name())
			}

			// Test DNS queries
			tests := []struct {
				name   string
				qname  string
				qtype  uint16
				expect bool
			}{
				{
					name:   "Service query",
					qname:  "kubernetes.default.svc.cluster.local.",
					qtype:  dns.TypeA,
					expect: true,
				},
				{
					name:   "Headless service",
					qname:  "headless.default.svc.cluster.local.",
					qtype:  dns.TypeA,
					expect: true,
				},
				{
					name:   "External service",
					qname:  "external.default.svc.cluster.local.",
					qtype:  dns.TypeCNAME,
					expect: true,
				},
				{
					name:   "Pod query",
					qname:  "10-244-1-10.default.pod.cluster.local.",
					qtype:  dns.TypeA,
					expect: true,
				},
				{
					name:   "StatefulSet pod",
					qname:  "web-0.nginx.default.svc.cluster.local.",
					qtype:  dns.TypeA,
					expect: true,
				},
				{
					name:   "SRV query",
					qname:  "_https._tcp.kubernetes.default.svc.cluster.local.",
					qtype:  dns.TypeSRV,
					expect: true,
				},
				{
					name:   "PTR query",
					qname:  "1.0.96.10.in-addr.arpa.",
					qtype:  dns.TypePTR,
					expect: true,
				},
				{
					name:   "Non-cluster query",
					qname:  "example.com.",
					qtype:  dns.TypeA,
					expect: false,
				},
			}

			ctx := context.Background()

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					req := new(dns.Msg)
					req.SetQuestion(tt.qname, tt.qtype)

					w := &mockResponseWriter{}

					ch := &middleware.Chain{
						Writer:  w,
						Request: req,
					}

					k8s.ServeDNS(ctx, ch)

					if tt.expect && w.msg == nil {
						t.Error("Expected response but got none")
					}

					if !tt.expect && w.msg != nil {
						t.Error("Expected no response but got one")
					}

					if tt.expect && w.msg != nil {
						// Verify response
						if w.msg.Rcode != dns.RcodeSuccess && w.msg.Rcode != dns.RcodeNameError {
							t.Errorf("Unexpected rcode: %d", w.msg.Rcode)
						}

						if w.msg.Rcode == dns.RcodeSuccess && len(w.msg.Answer) == 0 {
							t.Error("Success response with no answers")
						}
					}
				})
			}
		})
	}
}

// TestRegistry tests the registry
func TestRegistry(t *testing.T) {
	r := NewRegistry()

	// Test service operations
	svc := &Service{
		Name:       "test",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 1}},
		IPFamilies: []string{"IPv4"},
	}

	r.AddService(svc)

	retrieved := r.GetService("test", "default")
	if retrieved == nil {
		t.Fatal("Failed to retrieve service")
	}

	if retrieved.Name != "test" {
		t.Errorf("Expected name 'test', got %s", retrieved.Name)
	}

	// Test endpoints
	endpoints := []Endpoint{
		{Addresses: []string{"10.1.1.1"}, Ready: true},
		{Addresses: []string{"10.1.1.2"}, Ready: true},
	}

	r.SetEndpoints("test", "default", endpoints)

	eps := r.GetEndpoints("test", "default")
	if len(eps) != 2 {
		t.Errorf("Expected 2 endpoints, got %d", len(eps))
	}

	// Test pods
	pod := &Pod{
		Name:      "test-pod",
		Namespace: "default",
		IPs:       []string{"10.244.1.10"},
	}

	r.AddPod(pod)

	byName := r.GetPodByName("test-pod", "default")
	if byName == nil {
		t.Fatal("Failed to retrieve pod by name")
	}

	byIP := r.GetPodByIP("10.244.1.10")
	if byIP == nil {
		t.Fatal("Failed to retrieve pod by IP")
	}

	// Test stats
	stats := r.Stats()
	if stats["services"] != 1 {
		t.Errorf("Expected 1 service, got %d", stats["services"])
	}
	if stats["endpoints"] != 2 {
		t.Errorf("Expected 2 endpoints, got %d", stats["endpoints"])
	}
	if stats["pods"] != 1 {
		t.Errorf("Expected 1 pod, got %d", stats["pods"])
	}
}
