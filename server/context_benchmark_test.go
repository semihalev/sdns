package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	cachemw "github.com/semihalev/sdns/middleware/cache"
)

func BenchmarkServeDNSPipelineOverhead(b *testing.B) {
	cfg := &config.Config{QueryTimeout: config.Duration{Duration: 10 * time.Second}}
	handler := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		ch.Cancel()
	})
	s := serverWithHandler(cfg, handler)
	req := new(dns.Msg)
	req.SetQuestion("pipeline.example.", dns.TypeA)
	writer := mock.NewWriter("udp", "192.0.2.1:53000")

	b.ReportAllocs()
	for b.Loop() {
		s.ServeDNS(writer, req)
	}
}

func BenchmarkServeDNSPositiveCacheHit(b *testing.B) {
	cfg := &config.Config{
		CacheSize:    1024,
		Expire:       300,
		DNSSEC:       "off",
		QueryTimeout: config.Duration{Duration: 10 * time.Second},
	}
	cache := cachemw.New(cfg)
	defer cache.Stop()

	var backendCalls atomic.Uint64
	backend := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		backendCalls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   ch.Request.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	registry := middleware.NewRegistry()
	registry.Register("cache", func(*config.Config) middleware.Handler { return cache })
	registry.Register("backend", func(*config.Config) middleware.Handler { return backend })
	s := &Server{cfg: cfg, pipeline: registry.Build(cfg)}

	req := new(dns.Msg)
	req.SetQuestion("cached.example.", dns.TypeA)
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	s.ServeDNS(writer, req)
	if got := backendCalls.Load(); got != 1 {
		b.Fatalf("cache prime called backend %d times, want 1", got)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.ServeDNS(writer, req)
	}
	b.StopTimer()
	if got := backendCalls.Load(); got != 1 {
		b.Fatalf("cache hit benchmark called backend %d times, want 1", got)
	}
}
