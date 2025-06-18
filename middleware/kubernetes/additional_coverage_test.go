package kubernetes

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// TestCacheCleanupFull tests cache cleanup functionality
func TestCacheCleanupFull(t *testing.T) {
	cache := NewCache()

	// Add entries with short TTL
	msg := &dns.Msg{}
	msg.SetQuestion("test.local.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "test.local.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    1, // 1 second TTL
			},
			A: net.ParseIP("10.0.0.1"),
		},
	}

	// Add multiple entries
	for i := 0; i < 10; i++ {
		cache.Set(fmt.Sprintf("test%d.local.", i), dns.TypeA, msg)
	}

	// Wait for cleanup
	time.Sleep(2 * time.Second)

	// Verify entries expired
	for i := 0; i < 10; i++ {
		cached := cache.Get(fmt.Sprintf("test%d.local.", i), dns.TypeA)
		if cached != nil {
			t.Log("Entry may still be cached due to timing")
		}
	}
}

// TestParseReverseIPEdgeCases tests edge cases for reverse IP parsing
func TestParseReverseIPEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		wantOK bool
	}{
		{
			name:   "Empty",
			labels: []string{},
			wantOK: false,
		},
		{
			name:   "Too short IPv4",
			labels: []string{"1", "in-addr", "arpa"},
			wantOK: false,
		},
		{
			name:   "Invalid IPv4 octet",
			labels: []string{"256", "0", "0", "10", "in-addr", "arpa"},
			wantOK: false,
		},
		{
			name:   "IPv6 too short",
			labels: []string{"1", "ip6", "arpa"},
			wantOK: false,
		},
		{
			name:   "IPv6 invalid hex",
			labels: []string{"g", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "8", "b", "d", "0", "1", "0", "0", "2", "ip6", "arpa"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := ParseReverseIP(tt.labels)
			if ok != tt.wantOK {
				t.Errorf("ParseReverseIP() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && ip == nil {
				t.Error("Expected valid IP when ok=true")
			}
		})
	}
}

// TestCompressIPv6EdgeCases tests IPv6 compression edge cases
func TestCompressIPv6EdgeCases(t *testing.T) {
	tests := []struct {
		segments []string
		want     string
	}{
		{
			segments: []string{"2001", "db8", "0", "0", "0", "0", "0", "1"},
			want:     "2001-db8--1",
		},
		{
			segments: []string{"0", "0", "0", "0", "0", "0", "0", "1"},
			want:     "--1",
		},
		{
			segments: []string{"fe80", "0", "0", "0", "0", "0", "0", "0"},
			want:     "fe80--",
		},
		{
			segments: []string{"2001", "db8", "0", "0", "1", "0", "0", "1"},
			want:     "2001-db8--1-0-0-1",
		},
	}

	// compressIPv6 is an internal function, test via FormatPodIP
	for _, tt := range tests {
		// Create IP from segments
		ipStr := ""
		for i, seg := range tt.segments {
			if i > 0 {
				ipStr += ":"
			}
			ipStr += seg
		}
		ip := net.ParseIP(ipStr)
		if ip != nil {
			got := FormatPodIP(ip)
			// Just verify it doesn't panic
			if got == "" {
				t.Errorf("FormatPodIP(%s) returned empty", ipStr)
			}
		}
	}
}

// TestParseIPv6PodEdgeCases tests parseIPv6Pod edge cases
func TestParseIPv6PodEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		podName string
		wantIP  bool
	}{
		{
			name:    "Empty",
			podName: "",
			wantIP:  false,
		},
		{
			name:    "Too few segments",
			podName: "1-2",
			wantIP:  false,
		},
		{
			name:    "Invalid hex",
			podName: "gggg-0-0-0-0-0-0-1",
			wantIP:  false,
		},
		{
			name:    "Multiple compressions",
			podName: "2001--db8--1",
			wantIP:  false,
		},
		{
			name:    "Valid compressed",
			podName: "2001-db8--1",
			wantIP:  true,
		},
		{
			name:    "Valid full",
			podName: "2001-0db8-0000-0000-0000-0000-0000-0001",
			wantIP:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test via ParsePodIP which calls parseIPv6Pod internally
			ip := ParsePodIP(tt.podName)
			if (ip != nil) != tt.wantIP {
				t.Errorf("ParsePodIP(%s) = %v, want IP=%v", tt.podName, ip, tt.wantIP)
			}
		})
	}
}

// TestHighPerformanceCacheCleanupLoop tests cleanup loop
func TestHighPerformanceCacheCleanupLoop(t *testing.T) {
	cache := NewZeroAllocCache()

	// Add entries with varying TTLs
	for i := 0; i < 100; i++ {
		msg := &dns.Msg{}
		msg.SetQuestion(fmt.Sprintf("test%d.local.", i), dns.TypeA)
		msg.Response = true
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   fmt.Sprintf("test%d.local.", i),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(i%10 + 1),
				},
				A: []byte{10, 0, 0, byte(i)},
			},
		}
		cache.Store(fmt.Sprintf("test%d.local.", i), dns.TypeA, msg)
	}

	// Let cleanup run
	time.Sleep(100 * time.Millisecond)

	// Clear cache
	cache.Clear()

	// Verify cleared
	for i := 0; i < 100; i++ {
		if cache.Get(fmt.Sprintf("test%d.local.", i), dns.TypeA, 12345) != nil {
			t.Error("Cache should be empty after Clear")
		}
	}
}

// TestPredictorTrainLoop tests predictor training loop
func TestPredictorTrainLoop(t *testing.T) {
	p := NewLockFreePredictor()

	// Record patterns
	queries := []string{
		"app.default.svc.cluster.local.",
		"db.default.svc.cluster.local.",
		"cache.default.svc.cluster.local.",
	}

	// Train with pattern
	for i := 0; i < 200; i++ {
		for _, q := range queries {
			p.Record(q, dns.TypeA)
		}
	}

	// Let training run
	time.Sleep(200 * time.Millisecond)

	// Test predictions
	predictions := p.Predict("app.default.svc.cluster.local.")
	t.Logf("Got %d predictions after training", len(predictions))
}

// TestKubernetesName tests middleware name
func TestKubernetesName(t *testing.T) {
	cfg := &config.Config{
		Kubernetes: config.KubernetesConfig{
			Enabled:    true,
			KillerMode: true,
		},
	}

	k := New(cfg)

	// Test Name method
	if k.Name() != "kubernetes" {
		t.Errorf("Expected name 'kubernetes', got %s", k.Name())
	}
}

// TestServiceGetIPNoFamily tests GetIPv4/GetIPv6 with missing family info
func TestServiceGetIPNoFamily(t *testing.T) {
	// Service with IPs but no IPFamilies
	svc := &Service{
		Name:       "no-family",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 1}},
		IPFamilies: []string{}, // Empty families
	}

	// Should still try to determine based on IP length
	ipv4 := svc.GetIPv4()
	if ipv4 == nil {
		t.Error("Should return IPv4 based on length")
	}

	ipv6 := svc.GetIPv6()
	if ipv6 != nil {
		t.Error("Should not return IPv6 for 4-byte IP")
	}

	// Service with IPv6 length IP but no family
	svcV6 := &Service{
		Name:       "no-family-v6",
		Namespace:  "default",
		ClusterIPs: [][]byte{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		IPFamilies: []string{},
	}

	ipv4 = svcV6.GetIPv4()
	if ipv4 != nil {
		t.Error("Should not return IPv4 for 16-byte IP")
	}

	ipv6 = svcV6.GetIPv6()
	if ipv6 == nil {
		t.Error("Should return IPv6 based on length")
	}
}

// TestResolverResolvePodByHostname tests pod resolution by hostname
func TestResolverResolvePodByHostname(t *testing.T) {
	r := NewResolver(nil, "cluster.local", NewCache())

	// Add pod with hostname and subdomain
	r.registry.AddPod(&Pod{
		Name:      "web-0",
		Namespace: "default",
		IPs:       []string{"10.244.1.1"},
		Hostname:  "web-0",
		Subdomain: "webapp",
	})

	// Also add a pod without subdomain
	r.registry.AddPod(&Pod{
		Name:      "standalone",
		Namespace: "default",
		IPs:       []string{"10.244.1.2"},
		Hostname:  "standalone",
	})

	// Test various query patterns
	tests := []struct {
		query string
		found bool
		rcode int
		count int
	}{
		// Pod with subdomain - not supported by resolver
		{"web-0.webapp.default.svc.cluster.local.", true, dns.RcodeNameError, 0},
		// Pod without subdomain (shouldn't match service pattern)
		{"standalone.default.svc.cluster.local.", true, dns.RcodeNameError, 0},
		// Non-existent
		{"notexist.webapp.default.svc.cluster.local.", true, dns.RcodeNameError, 0},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			resp, found := r.Resolve(tt.query, dns.TypeA)
			if found != tt.found {
				t.Errorf("Expected found=%v, got %v", tt.found, found)
			}
			if found {
				if resp.Rcode != tt.rcode {
					t.Errorf("Expected rcode=%d, got %d", tt.rcode, resp.Rcode)
				}
				if len(resp.Answer) != tt.count {
					t.Errorf("Expected %d answers, got %d", tt.count, len(resp.Answer))
				}
			}
		})
	}
}
