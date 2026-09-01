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
					// Demo=true opts the middleware into its
					// synthetic service registry so tests
					// don't need a live cluster. Enabled
					// stays false, an enabled+failed
					// deployment must not silently fall back
					// to demo data in production.
					Demo:          true,
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
						Request: middleware.NewRequest(req),
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

// TestServeDNSAuthoritativeNXDOMAIN reproduces the regression where
// cluster-domain misses fell through to the next handler instead of
// returning authoritative NXDOMAIN. With kubernetes ahead of cache
// and resolver in the chain, that fall-through could leak a typo to
// public DNS, most dangerous with custom cluster domains where the
// public namesake might exist.
func TestServeDNSAuthoritativeNXDOMAIN(t *testing.T) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled: false, Demo: true, ClusterDomain: "cluster.local",
		},
	}
	k := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("nope.default.svc.cluster.local.", dns.TypeA)
	w := &mockResponseWriter{}
	ch := middleware.NewChain([]middleware.Handler{k})
	ch.Reset(w, req)

	k.ServeDNS(context.Background(), ch)

	if !w.Written() {
		t.Fatal("expected an authoritative response, got fall-through")
	}
	if w.Rcode() != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got rcode %d", w.Rcode())
	}
	if !w.Msg().Authoritative {
		t.Error("response must have AA bit set")
	}
}

// TestServeDNSSERVFAILWhenNotSynced pins the contract that
// cluster-domain queries return SERVFAIL, not pass through,
// when the middleware is configured but the registry isn't ready
// yet. Falling through could leak internal service names to
// public DNS, especially with a custom cluster_domain that has a
// real public namesake.
func TestServeDNSSERVFAILWhenNotSynced(t *testing.T) {
	// Build a Kubernetes middleware with a registry but no
	// client and no demo data, ready() returns false.
	k := &Kubernetes{
		registry:      NewRegistry(),
		clusterDomain: "cluster.local",
	}
	k.registry.SetClusterDomain("cluster.local")

	req := new(dns.Msg)
	req.SetQuestion("svc.default.svc.cluster.local.", dns.TypeA)
	w := &mockResponseWriter{}
	next := &fallthroughHandler{}
	ch := middleware.NewChain([]middleware.Handler{k, next})
	ch.Reset(w, req)

	k.ServeDNS(context.Background(), ch)

	if !w.Written() {
		t.Fatal("cluster-domain query while unsynced must SERVFAIL, not fall through")
	}
	if w.Rcode() != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL (rcode %d), got %d", dns.RcodeServerFailure, w.Rcode())
	}
	if next.called {
		t.Error("next handler must not be reached for an unsynced cluster-domain query")
	}
}

// TestServeDNSReverseFallsThroughWhenNotSynced verifies the
// SERVFAIL change didn't accidentally extend to reverse queries.
// The middleware never claims authority over in-addr.arpa /
// ip6.arpa without operator-configured cluster CIDRs, so reverse
// queries must always pass through, synced or not.
func TestServeDNSReverseFallsThroughWhenNotSynced(t *testing.T) {
	k := &Kubernetes{
		registry:      NewRegistry(),
		clusterDomain: "cluster.local",
	}
	k.registry.SetClusterDomain("cluster.local")

	req := new(dns.Msg)
	req.SetQuestion("8.8.8.8.in-addr.arpa.", dns.TypePTR)
	w := &mockResponseWriter{}
	next := &fallthroughHandler{}
	ch := middleware.NewChain([]middleware.Handler{k, next})
	ch.Reset(w, req)

	k.ServeDNS(context.Background(), ch)

	if w.Written() {
		t.Fatalf("public reverse query while unsynced must fall through, not SERVFAIL (rcode=%d)", w.Rcode())
	}
	if !next.called {
		t.Error("public reverse query must reach the next middleware via ch.Next")
	}
}

// TestClusterDomainNormalization covers the trailing-dot and
// mixed-case input handling in New(). Without normalisation a
// trailing dot built ".svc.cluster.local.." (double dot) and
// suffix-matching against a lowercased query name failed
// silently for any uppercase input.
func TestClusterDomainNormalization(t *testing.T) {
	cases := []string{
		"cluster.local",
		"cluster.local.",
		"Cluster.Local",
		"CLUSTER.LOCAL.",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			cfg := &config.Config{
				Kubernetes: config.KubernetesConfig{
					Demo: true, ClusterDomain: input,
				},
			}
			k := New(cfg)
			if k.clusterDomain != "cluster.local" {
				t.Errorf("input %q: expected cluster.local, got %q", input, k.clusterDomain)
			}

			req := new(dns.Msg)
			req.SetQuestion("kubernetes.default.svc.cluster.local.", dns.TypeA)
			w := &mockResponseWriter{}
			ch := middleware.NewChain([]middleware.Handler{k})
			ch.Reset(w, req)
			k.ServeDNS(context.Background(), ch)

			if !w.Written() {
				t.Fatal("expected an authoritative response, got fall-through")
			}
			if w.Rcode() != dns.RcodeSuccess {
				t.Errorf("expected NOERROR, got rcode %d", w.Rcode())
			}
		})
	}
}

// TestServeDNSPublicReverseFallsThrough pins the contract that
// reverse-zone misses fall through to the next middleware. Without
// operator-configured cluster CIDRs we can't tell a Kubernetes pod
// IP from a public address, so claiming authority over every
// in-addr.arpa / ip6.arpa name would NXDOMAIN public PTR queries
// (8.8.8.8.in-addr.arpa, etc.) the recursive resolver should answer.
func TestServeDNSPublicReverseFallsThrough(t *testing.T) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled: false, Demo: true, ClusterDomain: "cluster.local",
		},
	}
	k := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("8.8.8.8.in-addr.arpa.", dns.TypePTR)

	w := &mockResponseWriter{}
	next := &fallthroughHandler{}
	ch := middleware.NewChain([]middleware.Handler{k, next})
	ch.Reset(w, req)

	k.ServeDNS(context.Background(), ch)

	if w.Written() {
		t.Fatalf("public PTR must not be authoritatively answered (rcode=%d)", w.Rcode())
	}
	if !next.called {
		t.Error("public PTR must reach the next middleware via ch.Next")
	}
}

type fallthroughHandler struct{ called bool }

func (h *fallthroughHandler) Name() string { return "fallthrough" }
func (h *fallthroughHandler) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	h.called = true
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

	r.AddService(svc) //nolint:gosec // G104 - test setup

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

	r.SetEndpoints("test", "default", endpoints) //nolint:gosec // G104 - test setup

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

	r.AddPod(pod) //nolint:gosec // G104 - test setup

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
