package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func BenchmarkCacheEntryMemory(b *testing.B) {
	// Create a typical DNS response
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{1, 2, 3, 4},
	})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entry := NewCacheEntry(msg, 300*time.Second, 10)
		if entry == nil {
			b.Fatal("Failed to create cache entry")
		}
	}
}

func BenchmarkCacheEntryToMsg(b *testing.B) {
	// Create a cache entry
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{1, 2, 3, 4},
	})

	entry := NewCacheEntry(msg, 300*time.Second, 10)
	if entry == nil {
		b.Fatal("Failed to create cache entry")
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp := entry.ToMsg(req)
		if resp == nil {
			b.Fatal("Failed to convert cache entry to message")
		}
	}
}

// Benchmark memory usage with 1M entries
func BenchmarkCacheMemoryUsage(b *testing.B) {
	entries := make([]*CacheEntry, 0, 1000000)

	// Create various types of DNS responses
	for i := 0; i < 1000000; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.Response = true

		// Mix of response types
		switch i % 3 {
		case 0:
			// A record
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
			})
		case 1:
			// NXDOMAIN
			msg.Rcode = dns.RcodeNameError
		case 2:
			// SERVFAIL with EDE
			msg.Rcode = dns.RcodeServerFailure
			opt := &dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			}
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{
				InfoCode:  dns.ExtendedErrorCodeNetworkError,
				ExtraText: "Network unreachable",
			})
			msg.Extra = append(msg.Extra, opt)
		}

		entry := NewCacheEntry(msg, 300*time.Second, 10)
		if entry != nil {
			entries = append(entries, entry)
		}
	}

	b.Logf("Created %d cache entries", len(entries))
}
