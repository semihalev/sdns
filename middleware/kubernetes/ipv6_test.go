package kubernetes

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// TestIPv6PodParsing tests IPv6 pod query parsing
func TestIPv6PodParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IPv4", "10-244-1-1", "10.244.1.1"},
		{"IPv6 compressed", "2001-db8--1", "2001:db8::1"},
		{"IPv6 full", "2001-0db8-0000-0000-0000-0000-0000-0001", "2001:db8::1"},
		{"IPv6 mixed", "fd00-1-2-3-4-5-6-7", "fd00:1:2:3:4:5:6:7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := ParsePodIP(tt.input)
			if ip == nil {
				t.Fatalf("Failed to parse %s", tt.input)
			}
			if ip.String() != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, ip.String())
			}
		})
	}
}

// TestIPv6PodFormatting tests pod IP formatting for DNS
func TestIPv6PodFormatting(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"IPv4", "10.244.1.1", "10-244-1-1"},
		{"IPv6 compressed", "2001:db8::1", "2001-db8--1"},
		{"IPv6 full", "2001:db8:0:0:0:0:0:1", "2001-db8--1"},
		{"IPv6 complex", "fd00:1:2:3:4:5:6:7", "fd00-1-2-3-4-5-6-7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP: %s", tt.ip)
			}

			formatted := FormatPodIP(ip)
			if formatted != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, formatted)
			}
		})
	}
}

// TestIPv6ReverseParsing tests reverse DNS parsing for IPv6
func TestIPv6ReverseParsing(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		wantIP string
		wantOK bool
	}{
		{
			name:   "IPv4",
			labels: []string{"1", "0", "96", "10", "in-addr", "arpa"},
			wantIP: "10.96.0.1",
			wantOK: true,
		},
		{
			name:   "IPv6",
			labels: []string{"1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "8", "b", "d", "0", "1", "0", "0", "2", "ip6", "arpa"},
			wantIP: "2001:db8::1",
			wantOK: true,
		},
		{
			name:   "Invalid",
			labels: []string{"invalid"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := ParseReverseIP(tt.labels)
			if ok != tt.wantOK {
				t.Errorf("Expected ok=%v, got %v", tt.wantOK, ok)
			}
			if ok && ip.String() != tt.wantIP {
				t.Errorf("Expected IP %s, got %s", tt.wantIP, ip.String())
			}
		})
	}
}

// TestDualStackService tests dual-stack service support
func TestDualStackService(t *testing.T) {
	svc := &Service{
		Name:      "dual-stack",
		Namespace: "default",
		ClusterIPs: [][]byte{
			{10, 96, 0, 1}, // IPv4
			{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // IPv6
		},
		IPFamilies: []string{"IPv4", "IPv6"},
	}

	// Test GetIPv4
	ipv4 := svc.GetIPv4()
	if ipv4 == nil {
		t.Fatal("GetIPv4 returned nil")
	}
	if !net.IP(ipv4).Equal(net.ParseIP("10.96.0.1")) {
		t.Errorf("Wrong IPv4: %v", net.IP(ipv4))
	}

	// Test GetIPv6
	ipv6 := svc.GetIPv6()
	if ipv6 == nil {
		t.Fatal("GetIPv6 returned nil")
	}
	if !net.IP(ipv6).Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("Wrong IPv6: %v", net.IP(ipv6))
	}
}

// TestDualStackPod tests dual-stack pod support
func TestDualStackPod(t *testing.T) {
	pod := &Pod{
		Name:      "dual-stack-pod",
		Namespace: "default",
		IPs:       []string{"10.244.1.1", "2001:db8::100"},
	}

	// Test GetIPv4
	ipv4 := pod.GetIPv4()
	if ipv4 != "10.244.1.1" {
		t.Errorf("Expected IPv4 10.244.1.1, got %s", ipv4)
	}

	// Test GetIPv6
	ipv6 := pod.GetIPv6()
	if ipv6 != "2001:db8::100" {
		t.Errorf("Expected IPv6 2001:db8::100, got %s", ipv6)
	}
}

// TestDualStackEndpoint tests dual-stack endpoint support
func TestDualStackEndpoint(t *testing.T) {
	ep := &Endpoint{
		Addresses: []string{"10.1.1.1", "fd00::1"},
		Ready:     true,
	}

	// Test GetIPv4
	ipv4 := ep.GetIPv4()
	if ipv4 != "10.1.1.1" {
		t.Errorf("Expected IPv4 10.1.1.1, got %s", ipv4)
	}

	// Test GetIPv6
	ipv6 := ep.GetIPv6()
	if ipv6 != "fd00::1" {
		t.Errorf("Expected IPv6 fd00::1, got %s", ipv6)
	}
}

// TestIPv6ShardedRegistry tests IPv6 support in sharded registry
func TestIPv6ShardedRegistry(t *testing.T) {
	r := NewShardedRegistry()

	// Add IPv6 service
	r.AddService(&Service{
		Name:      "ipv6-svc",
		Namespace: "default",
		ClusterIPs: [][]byte{
			{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // 2001:db8::1
		},
		IPFamilies: []string{"IPv6"},
	})

	// Query AAAA record
	answers, found := r.ResolveQuery("ipv6-svc.default.svc.cluster.local.", dns.TypeAAAA)
	if !found {
		t.Fatal("Service not found")
	}
	if len(answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(answers))
	}

	aaaa, ok := answers[0].(*dns.AAAA)
	if !ok {
		t.Fatal("Expected AAAA record")
	}
	if !aaaa.AAAA.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("Wrong IPv6: %v", aaaa.AAAA)
	}

	// Add IPv6 pod
	r.AddPod(&Pod{
		Name:      "ipv6-pod",
		Namespace: "default",
		IPs:       []string{"2001:db8::100"},
	})

	// Query pod by IPv6
	answers, found = r.ResolveQuery("2001-db8--100.default.pod.cluster.local.", dns.TypeAAAA)
	if !found {
		t.Fatal("Pod not found")
	}
	if len(answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(answers))
	}

	// Test IPv6 PTR
	answers, found = r.ResolveQuery("0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", dns.TypePTR)
	if !found {
		t.Fatal("PTR not found")
	}
	if len(answers) != 1 {
		t.Fatalf("Expected 1 PTR answer, got %d", len(answers))
	}

	ptr, ok := answers[0].(*dns.PTR)
	if !ok {
		t.Fatal("Expected PTR record")
	}
	if ptr.Ptr != "2001-db8--100.default.pod.cluster.local." {
		t.Errorf("Wrong PTR target: %s", ptr.Ptr)
	}
}

// TestFullIPv6Compatibility tests complete IPv6 support
func TestFullIPv6Compatibility(t *testing.T) {
	r := NewRegistry()

	// Test GetServiceByIP with IPv6
	svc := &Service{
		Name:      "test",
		Namespace: "default",
		ClusterIPs: [][]byte{
			{10, 96, 0, 1}, // IPv4
			{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, // IPv6
		},
		IPFamilies: []string{"IPv4", "IPv6"},
	}
	r.AddService(svc)

	// Find by IPv4
	found := r.GetServiceByIP([]byte{10, 96, 0, 1})
	if found == nil || found.Name != "test" {
		t.Error("Failed to find service by IPv4")
	}

	// Find by IPv6
	found = r.GetServiceByIP([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	if found == nil || found.Name != "test" {
		t.Error("Failed to find service by IPv6")
	}

	// Test pod with multiple IPs
	pod := &Pod{
		Name:      "multi-ip",
		Namespace: "default",
		IPs:       []string{"10.244.1.1", "fd00::1", "2001:db8::100"},
	}
	r.AddPod(pod)

	// Find by any IP
	for _, ip := range pod.IPs {
		found := r.GetPodByIP(ip)
		if found == nil || found.Name != "multi-ip" {
			t.Errorf("Failed to find pod by IP %s", ip)
		}
	}
}
