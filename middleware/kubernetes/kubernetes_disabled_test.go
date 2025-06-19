package kubernetes

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
)

// mockHandler tracks if ServeDNS was called
type mockHandler struct {
	called bool
}

func (m *mockHandler) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	m.called = true
}

func (m *mockHandler) Name() string {
	return "mock"
}

// TestKubernetesDisabled tests that disabled Kubernetes middleware passes through correctly
func TestKubernetesDisabled(t *testing.T) {
	// Create config with Kubernetes disabled
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled: false,
		},
	}

	// Create middleware
	k := New(cfg)

	// Test that it has the minimal fields set
	if k.clusterDomain != "cluster.local" {
		t.Errorf("Expected cluster domain to be 'cluster.local', got %s", k.clusterDomain)
	}

	// Ensure resolver and registry are nil
	if k.resolver != nil {
		t.Error("Expected resolver to be nil when disabled")
	}
	if k.registry != nil {
		t.Error("Expected registry to be nil when disabled")
	}

	// Test ServeDNS passes through without panic
	w := mock.NewWriter("udp", "127.0.0.1:53")
	req := new(dns.Msg)
	req.SetQuestion("kubernetes.default.svc.cluster.local.", dns.TypeA)

	// Create a chain with a mock handler
	mockNext := &mockHandler{}
	ch := middleware.NewChain([]middleware.Handler{mockNext})
	ch.Writer = w
	ch.Request = req

	// This should not panic and should pass through
	k.ServeDNS(context.Background(), ch)

	if !mockNext.called {
		t.Error("Expected ServeDNS to call Next() when disabled")
	}

	// Test Stats() doesn't panic
	stats := k.Stats()
	if stats == nil {
		t.Error("Expected Stats() to return non-nil map")
	}
}

// TestKubernetesNilConfig tests that nil Kubernetes config is handled
func TestKubernetesNilConfig(t *testing.T) {
	// Create config with nil Kubernetes section
	cfg := &config.Config{}

	// Create middleware - should not panic
	k := New(cfg)

	// Should be disabled by default
	if k.resolver != nil {
		t.Error("Expected resolver to be nil with default config")
	}

	// Test ServeDNS
	w := mock.NewWriter("udp", "127.0.0.1:53")
	req := new(dns.Msg)
	req.SetQuestion("test.cluster.local.", dns.TypeA)

	// Create a chain with a mock handler
	mockNext := &mockHandler{}
	ch := middleware.NewChain([]middleware.Handler{mockNext})
	ch.Writer = w
	ch.Request = req

	k.ServeDNS(context.Background(), ch)

	if !mockNext.called {
		t.Error("Expected ServeDNS to call Next() when Kubernetes is not configured")
	}
}
