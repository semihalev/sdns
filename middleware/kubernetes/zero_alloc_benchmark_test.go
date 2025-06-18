package kubernetes

import (
	"fmt"
	"testing"
	"github.com/miekg/dns"
)

// BenchmarkZeroAllocCacheGet benchmarks cache retrieval (should be zero allocs)
func BenchmarkZeroAllocCacheGet(b *testing.B) {
	cache := NewZeroAllocCache()
	
	// Pre-populate cache with test data
	for i := 0; i < 100; i++ {
		qname := fmt.Sprintf("service-%d.default.svc.cluster.local.", i)
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
	
	// Reset timer to exclude setup
	b.ResetTimer()
	
	// Benchmark the GetEntry method
	b.Run("GetEntry", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Rotate through different queries
			qname := fmt.Sprintf("service-%d.default.svc.cluster.local.", i%100)
			wire := cache.GetEntry(qname, dns.TypeA)
			if wire == nil {
				b.Fatal("Cache miss")
			}
		}
	})
}

// BenchmarkZeroAllocCacheStore benchmarks cache storage
func BenchmarkZeroAllocCacheStore(b *testing.B) {
	cache := NewZeroAllocCache()
	
	// Pre-create wire format messages
	wires := make([][]byte, 100)
	qnames := make([]string, 100)
	for i := 0; i < 100; i++ {
		qname := fmt.Sprintf("bench-%d.test.cluster.local.", i)
		qnames[i] = qname
		msg := &dns.Msg{}
		msg.SetQuestion(qname, dns.TypeA)
		msg.Response = true
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: []byte{192, 168, 1, byte(i)},
			},
		}
		wire, _ := msg.Pack()
		wires[i] = wire
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		idx := i % 100
		cache.StoreWire(qnames[idx], dns.TypeA, wires[idx], 60)
	}
}

// BenchmarkStandardCacheComparison compares with standard cache
func BenchmarkStandardCacheComparison(b *testing.B) {
	// Standard cache for comparison
	stdCache := NewCache()
	
	// Pre-populate
	for i := 0; i < 100; i++ {
		qname := fmt.Sprintf("service-%d.default.svc.cluster.local.", i)
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
		stdCache.Set(qname, dns.TypeA, msg)
	}
	
	b.Run("StandardCache_Get", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			qname := fmt.Sprintf("service-%d.default.svc.cluster.local.", i%100)
			msg := stdCache.Get(qname, dns.TypeA)
			if msg == nil {
				b.Fatal("Cache miss")
			}
		}
	})
}

// BenchmarkZeroAllocCacheParallel tests concurrent access
func BenchmarkZeroAllocCacheParallel(b *testing.B) {
	cache := NewZeroAllocCache()
	
	// Pre-populate
	for i := 0; i < 1000; i++ {
		qname := fmt.Sprintf("parallel-%d.test.local.", i)
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
				A: []byte{10, 0, byte(i >> 8), byte(i)},
			},
		}
		wire, _ := msg.Pack()
		cache.StoreWire(qname, dns.TypeA, wire, 300)
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			qname := fmt.Sprintf("parallel-%d.test.local.", i%1000)
			wire := cache.GetEntry(qname, dns.TypeA)
			if wire == nil {
				b.Fatal("Cache miss")
			}
			i++
		}
	})
}