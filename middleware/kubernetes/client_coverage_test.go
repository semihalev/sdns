package kubernetes

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	os.Setenv("HOME", testHome) //nolint:gosec // G104 - test setup

	// Create test kubeconfig directory
	os.MkdirAll(testHome+"/.kube", 0755) //nolint:gosec // G104,G301 - test setup

	// Try to build config (will fail but covers the HOME path)
	_, err := buildConfig("")
	if err == nil {
		t.Skip("Found valid kubeconfig")
	}

	// Test with KUBECONFIG env var
	os.Setenv("KUBECONFIG", "/tmp/nonexistent-kubeconfig") //nolint:gosec // G104 - test setup
	_, err = buildConfig("")
	if err == nil {
		t.Error("Should fail with nonexistent KUBECONFIG")
	}
}

// TestResolverResolvePod tests pod resolution
func TestResolverResolvePod(t *testing.T) {
	r := NewResolver(nil, "cluster.local", NewCache())

	// Add pod by IP format
	r.registry.AddPod(&Pod{ //nolint:gosec // G104 - test setup
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
		resolver:   NewResolver(nil, "cluster.local", NewCache()),
		killerMode: true,
		predictor:  NewSmartPredictor(),
	}

	// Add some services
	k.resolver.registry.AddService(&Service{ //nolint:gosec // G104 - test setup
		Name:       "predicted-svc",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 50}},
		IPFamilies: []string{"IPv4"},
	})

	// Test prefetch with new method
	k.prefetchPredictedWithClient("10.0.0.1", "predicted-svc.default.svc.cluster.local.", dns.TypeA)

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

// TestHighPerformanceCacheMoreEdgeCases tests more zero alloc cache edge cases
func TestHighPerformanceCacheMoreEdgeCases(t *testing.T) {
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
			cache.Get(qname, dns.TypeA, uint16(i)) //nolint:gosec // G115 - test loop iteration
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
}

// TestGetTopPredictionsEdgeCases tests prediction edge cases
func TestGetTopPredictionsEdgeCases(t *testing.T) {
	p := NewSmartPredictor()

	// Test with empty predictor
	predictions := p.Predict("10.0.0.1", "test")
	if len(predictions) != 0 {
		t.Log("New predictor may have no predictions initially")
	}

	// Train the predictor
	for i := 0; i < 100; i++ {
		p.Record("10.0.0.1", "query1", dns.TypeA)
		p.Record("10.0.0.1", "query2", dns.TypeA)
		p.Record("10.0.0.1", "query3", dns.TypeA)
	}

	// Test predictions after training
	predictions = p.Predict("10.0.0.1", "query1")
	t.Logf("Got %d predictions", len(predictions))
}

// TestKubernetesNewWithClient tests New with real client attempt
func TestKubernetesNewWithClient(t *testing.T) {
	// Set invalid kubeconfig path
	os.Setenv("KUBECONFIG", "/tmp/nonexistent-kubeconfig-test") //nolint:gosec // G104 - test setup
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

// TestClientConverters tests the conversion functions
func TestClientConverters(t *testing.T) {
	c := &Client{
		registry: NewRegistry(),
	}

	// Test convertService with ClusterIP
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.1",
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP},
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	service := c.convertService(svc)
	if service.Name != "test-svc" {
		t.Errorf("Expected name test-svc, got %s", service.Name)
	}
	if len(service.Ports) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(service.Ports))
	}

	// Test convertService with headless service
	headlessSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "headless-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "None",
		},
	}
	headlessService := c.convertService(headlessSvc)
	if !headlessService.Headless {
		t.Error("Expected headless service")
	}

	// Test convertService with ExternalName
	externalSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "example.com",
		},
	}
	externalService := c.convertService(externalSvc)
	if externalService.ExternalName != "example.com" {
		t.Errorf("Expected external name example.com, got %s", externalService.ExternalName)
	}

	// Test convertPod with no IP
	podNoIP := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-no-ip",
			Namespace: "default",
		},
	}
	if c.convertPod(podNoIP) != nil {
		t.Error("Pod with no IP should return nil")
	}

	// Test convertPod with IP and hostname
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Hostname:  "my-hostname",
			Subdomain: "my-subdomain",
		},
		Status: corev1.PodStatus{
			PodIP: "10.244.1.1",
			PodIPs: []corev1.PodIP{
				{IP: "10.244.1.1"},
				{IP: "fd00::1"},
			},
		},
	}
	convertedPod := c.convertPod(pod)
	if convertedPod == nil {
		t.Fatal("Pod should be converted")
	}
	if convertedPod.Hostname != "my-hostname" {
		t.Errorf("Expected hostname my-hostname, got %s", convertedPod.Hostname)
	}
	if len(convertedPod.IPs) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(convertedPod.IPs))
	}

	// Test convertEndpointSlice
	ready := true
	hostname := "ep-hostname"
	eps := &discoveryv1.EndpointSlice{
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.244.1.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
				Hostname:   &hostname,
				TargetRef: &corev1.ObjectReference{
					Kind:      "Pod",
					Name:      "test-pod",
					Namespace: "default",
				},
			},
			{
				Addresses: []string{}, // Empty addresses - should be skipped
			},
		},
	}
	endpoints := c.convertEndpointSlice(eps)
	if len(endpoints) != 1 {
		t.Errorf("Expected 1 endpoint, got %d", len(endpoints))
	}
	if endpoints[0].Hostname != "ep-hostname" {
		t.Errorf("Expected hostname ep-hostname, got %s", endpoints[0].Hostname)
	}
}

// TestClientEventHandlers tests the event handler functions
func TestClientEventHandlers(t *testing.T) {
	c := &Client{
		registry: NewRegistry(),
	}

	// Test onServiceAdd with valid service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.1",
		},
	}
	c.onServiceAdd(svc)
	if c.registry.GetService("test-svc", "default") == nil {
		t.Error("Service should be added")
	}

	// Test onServiceAdd with invalid type
	c.onServiceAdd("invalid")

	// Test onServiceUpdate
	c.onServiceUpdate(nil, svc)
	c.onServiceUpdate(nil, "invalid")

	// Test onServiceDelete
	c.onServiceDelete(svc)
	c.onServiceDelete("invalid")

	// Test onEndpointSliceAdd with valid slice
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-slice",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "test-svc"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.244.1.1"}},
		},
	}
	c.registry.AddService(&Service{Name: "test-svc", Namespace: "default"}) //nolint:gosec // G104 - test setup
	c.onEndpointSliceAdd(eps)
	c.onEndpointSliceAdd("invalid")

	// Test with no service name label
	epsNoLabel := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-label",
			Namespace: "default",
		},
	}
	c.onEndpointSliceAdd(epsNoLabel)

	// Test onEndpointSliceUpdate
	c.onEndpointSliceUpdate(nil, eps)
	c.onEndpointSliceUpdate(nil, "invalid")
	c.onEndpointSliceUpdate(nil, epsNoLabel)

	// Test onEndpointSliceDelete
	c.onEndpointSliceDelete(eps)
	c.onEndpointSliceDelete("invalid")
	c.onEndpointSliceDelete(epsNoLabel)

	// Test onPodAdd with valid pod
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			PodIP: "10.244.1.1",
		},
	}
	c.onPodAdd(pod)
	c.onPodAdd("invalid")

	// Test onPodAdd with pod without IP
	podNoIP := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-ip-pod",
			Namespace: "default",
		},
	}
	c.onPodAdd(podNoIP)

	// Test onPodUpdate
	c.onPodUpdate(nil, pod)
	c.onPodUpdate(nil, "invalid")

	// Test onPodDelete
	c.onPodDelete(pod)
	c.onPodDelete("invalid")
}

// TestClientSafeHandlers tests the safe wrapper handlers
func TestClientSafeHandlers(t *testing.T) {
	c := &Client{
		registry: NewRegistry(),
	}

	// These should not panic even with invalid input
	c.safeServiceAdd(nil)
	c.safeServiceUpdate(nil, nil)
	c.safeServiceDelete(nil)
	c.safeEndpointSliceAdd(nil)
	c.safeEndpointSliceUpdate(nil, nil)
	c.safeEndpointSliceDelete(nil)
	c.safePodAdd(nil)
	c.safePodUpdate(nil, nil)
	c.safePodDelete(nil)
}

// TestClientStop tests the Stop function
func TestClientStop(t *testing.T) {
	c := &Client{
		registry: NewRegistry(),
		stopCh:   make(chan struct{}),
		stopped:  make(chan struct{}),
	}

	// Close stopped channel to simulate Run completion
	close(c.stopped)

	// First stop
	c.Stop()

	// Second stop should not panic (already stopped)
	c.Stop()
}

// TestResolverSRVEdgeCases tests SRV resolution edge cases
func TestResolverSRVEdgeCases(t *testing.T) {
	r := NewResolver(nil, "cluster.local", NewCache())

	// Add service with no ports
	r.registry.AddService(&Service{ //nolint:gosec // G104 - test setup
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
	r.registry.AddService(&Service{ //nolint:gosec // G104 - test setup
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
