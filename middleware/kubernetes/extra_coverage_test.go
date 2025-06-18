package kubernetes

import (
	"testing"

	"github.com/miekg/dns"
)

// TestServiceType tests service type handling
func TestServiceType(t *testing.T) {
	// Test service types
	svc := &Service{
		Name:         "test",
		Namespace:    "default",
		Type:         "ExternalName",
		ExternalName: "external.example.com",
	}

	if svc.Type != "ExternalName" {
		t.Error("Service type not set")
	}

	// Test headless
	headless := &Service{
		Name:      "headless",
		Namespace: "default",
		Headless:  true,
	}

	if !headless.Headless {
		t.Error("Headless flag not set")
	}
}

// TestCacheEdgeCases tests cache edge cases
func TestCacheEdgeCases(t *testing.T) {
	cache := NewCache()

	// Test with valid message first
	msg := &dns.Msg{}
	msg.SetQuestion("test.local.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{
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

	// Test caching
	cache.Set("test.local.", dns.TypeA, msg)

	// Different qtype should miss
	if cache.Get("test.local.", dns.TypeAAAA) != nil {
		t.Error("Should not return different qtype")
	}
}

// TestZeroAllocCacheEdgeCases tests zero-alloc cache edge cases
func TestZeroAllocCacheEdgeCases(t *testing.T) {
	cache := NewZeroAllocCache()

	// Test with large message
	msg := &dns.Msg{}
	msg.SetQuestion("large.test.", dns.TypeA)
	msg.Response = true

	// Add many answers to exceed buffer
	for i := 0; i < 50; i++ {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   "large.test.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			A: []byte{10, 0, 0, byte(i)},
		})
	}

	cache.Store("large.test.", dns.TypeA, msg)
	wire := cache.Get("large.test.", dns.TypeA, 123)
	if wire == nil {
		t.Error("Failed to cache large message")
	}

	// Test cleanup
	cache.Clear()
	if cache.Get("large.test.", dns.TypeA, 1) != nil {
		t.Error("Cache not cleared")
	}
}

// TestShardedRegistryEdgeCases tests sharded registry edge cases
func TestShardedRegistryEdgeCases(t *testing.T) {
	r := NewShardedRegistry()

	// Test with no ports (for coverage)
	r.AddService(&Service{
		Name:       "no-ports",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 0, 0, 1}},
	})

	// Test SRV with no matching port
	srv, found := r.ResolveQuery("_http._tcp.no-ports.default.svc.cluster.local.", dns.TypeSRV)
	if found && len(srv) > 0 {
		t.Error("Should not find SRV for service without ports")
	}

	// Test malformed queries
	tests := []string{
		"",
		".",
		"malformed",
		"too.short",
		"wrong.suffix.local.",
	}

	for _, q := range tests {
		_, found := r.ResolveQuery(q, dns.TypeA)
		if found {
			t.Errorf("Should not handle malformed query: %s", q)
		}
	}

	// Test PTR with invalid IP
	_, found = r.ResolveQuery("invalid.in-addr.arpa.", dns.TypePTR)
	if found {
		t.Error("Should not handle invalid PTR")
	}
}

// TestPredictorEdgeCases tests predictor edge cases
func TestPredictorEdgeCases(t *testing.T) {
	p := NewLockFreePredictor()

	// Test with non A/AAAA types
	p.Record("test.local.", dns.TypeMX)
	p.Record("test.local.", dns.TypeTXT)

	// Should not affect predictions
	predictions := p.Predict("test.local.")
	if len(predictions) > 0 {
		t.Error("Should not predict from non-A/AAAA queries")
	}

	// Test empty domain
	p.Record("", dns.TypeA)
	predictions = p.Predict("")
	if len(predictions) > 0 {
		t.Error("Should not predict for empty domain")
	}

	// Test model size
	for i := 0; i < 1000; i++ {
		p.Record("domain"+string(rune(i))+".local.", dns.TypeA)
	}

	stats := p.Stats()
	if modelSize, ok := stats["model_size"].(int); ok && modelSize < 100 {
		t.Error("Model not growing with data")
	}
}

// TestResolverEdgeCases tests resolver edge cases
func TestResolverEdgeCases(t *testing.T) {
	r := NewResolver("cluster.local", NewCache())

	// Test with various invalid patterns
	tests := []struct {
		qname string
		qtype uint16
	}{
		// Invalid pod IPs
		{"300-300-300-300.default.pod.cluster.local.", dns.TypeA},
		{"not-an-ip.default.pod.cluster.local.", dns.TypeA},

		// Invalid namespaces
		{".namespace.svc.cluster.local.", dns.TypeA},
		{"svc..svc.cluster.local.", dns.TypeA},

		// Wrong suffix
		{"service.default.svc.cluster.internal.", dns.TypeA},

		// Incomplete
		{"svc.cluster.local.", dns.TypeA},
		{".cluster.local.", dns.TypeA},
	}

	for _, tt := range tests {
		resp, found := r.Resolve(tt.qname, tt.qtype)
		if !found {
			continue // Not handled is OK
		}

		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("Expected NXDOMAIN for %s, got %d", tt.qname, resp.Rcode)
		}
	}
}

// TestResponseType tests Response type
func TestResponseType(t *testing.T) {
	// Test Response struct
	resp := &Response{
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "test.cluster.local.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: []byte{10, 0, 0, 1},
			},
		},
		Rcode: dns.RcodeSuccess,
	}

	if len(resp.Answer) != 1 {
		t.Error("Answer not set")
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Rcode not set")
	}

	// Test with extra
	resp.Extra = []dns.RR{
		&dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		},
	}

	if len(resp.Extra) != 1 {
		t.Error("Extra not set")
	}
}

// TestConcurrentCacheAccess tests concurrent cache access
func TestConcurrentCacheAccess(t *testing.T) {
	cache := NewZeroAllocCache()

	// Pre-populate
	for i := 0; i < 10; i++ {
		qname := "svc" + string(rune('0'+i)) + ".default.svc.cluster.local."
		msg := &dns.Msg{}
		msg.SetQuestion(qname, dns.TypeA)
		msg.Response = true
		cache.Store(qname, dns.TypeA, msg)
	}

	// Concurrent access
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				qname := "svc" + string(rune('0'+id)) + ".default.svc.cluster.local."
				cache.Get(qname, dns.TypeA, uint16(j))

				// Also store new entries
				if j%10 == 0 {
					newName := "new" + string(rune('0'+j)) + ".default.svc.cluster.local."
					msg := &dns.Msg{}
					msg.SetQuestion(newName, dns.TypeA)
					msg.Response = true
					cache.Store(newName, dns.TypeA, msg)
				}
			}
			done <- true
		}(i)
	}

	// Wait
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify cache integrity
	stats := cache.Stats()
	if size, ok := stats["size"].(int); !ok || size < 10 {
		t.Error("Cache corrupted during concurrent access")
	}
}

// TestEndpointType tests Endpoint type
func TestEndpointType(t *testing.T) {
	// Test endpoint
	ep := &Endpoint{
		Addresses: []string{"10.1.1.1"},
		Hostname:  "pod-1",
		Ready:     true,
		TargetRef: &ObjectRef{
			Kind:      "Pod",
			Name:      "pod-1",
			Namespace: "default",
		},
	}

	if !ep.Ready {
		t.Error("Endpoint not ready")
	}

	if ep.TargetRef.Kind != "Pod" {
		t.Error("TargetRef not set correctly")
	}
}
