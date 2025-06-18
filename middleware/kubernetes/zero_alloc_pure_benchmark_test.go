package kubernetes

import (
	"testing"
	"github.com/miekg/dns"
)

// BenchmarkPureZeroAllocCache tests the true zero-allocation behavior
func BenchmarkPureZeroAllocCache(b *testing.B) {
	cache := NewZeroAllocCache()
	
	// Pre-populate with fixed queries
	queries := []string{
		"svc1.default.svc.cluster.local.",
		"svc2.default.svc.cluster.local.",
		"svc3.default.svc.cluster.local.",
		"svc4.default.svc.cluster.local.",
		"svc5.default.svc.cluster.local.",
		"svc6.default.svc.cluster.local.",
		"svc7.default.svc.cluster.local.",
		"svc8.default.svc.cluster.local.",
		"svc9.default.svc.cluster.local.",
		"svc10.default.svc.cluster.local.",
	}
	
	for i, qname := range queries {
		msg := &dns.Msg{}
		msg.SetQuestion(qname, dns.TypeA)
		msg.Response = true
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: []byte{10, 96, 0, byte(i)},
			},
		}
		
		wire, _ := msg.Pack()
		cache.StoreWire(qname, dns.TypeA, wire, 300)
	}
	
	// Verify all entries are cached
	for _, qname := range queries {
		if cache.GetEntry(qname, dns.TypeA) == nil {
			b.Fatalf("Failed to cache %s", qname)
		}
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	// Benchmark with pre-allocated query rotation
	for i := 0; i < b.N; i++ {
		qname := queries[i%len(queries)]
		wire := cache.GetEntry(qname, dns.TypeA)
		if wire == nil {
			b.Fatal("Cache miss")
		}
		// Simulate reading the wire data (but don't allocate)
		if len(wire) < 12 {
			b.Fatal("Invalid wire format")
		}
	}
}

// BenchmarkZeroAllocWithMessageID shows the cost of updating message ID
func BenchmarkZeroAllocWithMessageID(b *testing.B) {
	cache := NewZeroAllocCache()
	
	// Pre-populate
	qname := "test.svc.cluster.local."
	msg := &dns.Msg{}
	msg.SetQuestion(qname, dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{10, 96, 0, 1},
		},
	}
	
	wire, _ := msg.Pack()
	cache.StoreWire(qname, dns.TypeA, wire, 300)
	
	// Pre-allocate a response buffer to reuse
	respBuf := make([]byte, 4096)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		wire := cache.GetEntry(qname, dns.TypeA)
		if wire == nil {
			b.Fatal("Cache miss")
		}
		
		// Copy to response buffer and update message ID
		// This simulates what happens in ServeDNS
		n := copy(respBuf, wire)
		UpdateMessageID(respBuf[:n], uint16(i))
	}
}

// BenchmarkHashFunction tests the hash function performance
func BenchmarkHashFunction(b *testing.B) {
	queries := []string{
		"kubernetes.default.svc.cluster.local.",
		"kube-dns.kube-system.svc.cluster.local.",
		"metrics-server.kube-system.svc.cluster.local.",
		"app-service.production.svc.cluster.local.",
		"database.production.svc.cluster.local.",
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		qname := queries[i%len(queries)]
		_ = hashKey(qname, dns.TypeA)
	}
}