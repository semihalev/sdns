package cache

import (
	"testing"

	"github.com/miekg/dns"
)

func BenchmarkMessagePool(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m := AcquireMsg()
				// Simulate typical DNS message usage
				m.SetQuestion("example.com.", dns.TypeA)
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{93, 184, 216, 34},
				})
				m.Extra = append(m.Extra, &dns.OPT{
					Hdr: dns.RR_Header{
						Name:   ".",
						Rrtype: dns.TypeOPT,
					},
				})
				ReleaseMsg(m)
			}
		})
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m := &dns.Msg{}
				// Simulate typical DNS message usage
				m.SetQuestion("example.com.", dns.TypeA)
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{93, 184, 216, 34},
				})
				m.Extra = append(m.Extra, &dns.OPT{
					Hdr: dns.RR_Header{
						Name:   ".",
						Rrtype: dns.TypeOPT,
					},
				})
			}
		})
	})
}

func BenchmarkMessagePoolLargeResponse(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m := AcquireMsg()
				m.SetQuestion("example.com.", dns.TypeA)
				// Add many answers
				for i := 0; i < 20; i++ {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: []byte{byte(i), 0, 0, 1},
					})
				}
				ReleaseMsg(m)
			}
		})
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m := &dns.Msg{}
				m.SetQuestion("example.com.", dns.TypeA)
				// Add many answers
				for i := 0; i < 20; i++ {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: []byte{byte(i), 0, 0, 1},
					})
				}
			}
		})
	})
}
