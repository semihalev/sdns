package reflex

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("disabled returns nil", func(t *testing.T) {
		cfg := &config.Config{ReflexEnabled: false}
		r := New(cfg)
		assert.Nil(t, r)
	})

	t.Run("enabled returns instance", func(t *testing.T) {
		cfg := &config.Config{ReflexEnabled: true}
		r := New(cfg)
		require.NotNil(t, r)
		assert.Equal(t, "reflex", r.Name())
		_ = r.Close()
	})
}

func TestServeDNS_SkipConditions(t *testing.T) {
	cfg := &config.Config{ReflexEnabled: true, ReflexBlockMode: true}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	t.Run("skip internal", func(t *testing.T) {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		mw := mock.NewWriter("udp", "127.0.0.255:0")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		assert.False(t, mw.Written())
	})

	t.Run("skip loopback", func(t *testing.T) {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		mw := mock.NewWriter("udp", "127.0.0.1:53")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		assert.False(t, mw.Written())
	})

	t.Run("TCP improves reputation", func(t *testing.T) {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		mw := mock.NewWriter("tcp", "192.168.1.100:12345")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		assert.False(t, mw.Written())

		// Check that TCP was recorded
		entry := r.tracker.GetEntry("192.168.1.100")
		if entry != nil {
			assert.True(t, entry.HasTCP)
		}
	})
}

func TestServeDNS_NormalTraffic(t *testing.T) {
	cfg := &config.Config{ReflexEnabled: true, ReflexBlockMode: true}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	// Normal A queries should pass
	for i := 0; i < 20; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		mw := mock.NewWriter("udp", "192.168.1.50:12345")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		assert.False(t, mw.Written(), "normal query %d should not be blocked", i)
	}
}

func TestServeDNS_AmplificationAttack(t *testing.T) {
	cfg := &config.Config{
		ReflexEnabled:   true,
		ReflexBlockMode: true,
	}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	ip := "203.0.113.100" // Attacker IP

	// Simulate amplification attack: only DNSKEY queries
	blocked := 0
	for i := 0; i < 50; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeDNSKEY)
		mw := mock.NewWriter("udp", ip+":12345")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		if mw.Written() && mw.Rcode() == dns.RcodeRefused {
			blocked++
		}
	}

	// Should eventually block
	assert.Greater(t, blocked, 0, "amplification attack should be detected")
	t.Logf("Blocked %d of 50 suspicious queries", blocked)
}

func TestServeDNS_MixedHighAmpQueries(t *testing.T) {
	cfg := &config.Config{
		ReflexEnabled:   true,
		ReflexBlockMode: true,
	}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	ip := "203.0.113.101"

	// Mix of high-amp queries without any normal queries
	highAmpTypes := []uint16{dns.TypeDNSKEY, dns.TypeTXT, dns.TypeNS, dns.TypeMX}
	blocked := 0

	for i := 0; i < 50; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		qtype := highAmpTypes[i%len(highAmpTypes)] //nolint:gosec // safe index
		req.SetQuestion("example.com.", qtype)
		mw := mock.NewWriter("udp", ip+":12345")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		if mw.Written() && mw.Rcode() == dns.RcodeRefused {
			blocked++
		}
	}

	t.Logf("Blocked %d of 50 high-amp queries", blocked)
}

func TestServeDNS_LegitimateHighAmpWithNormal(t *testing.T) {
	cfg := &config.Config{
		ReflexEnabled:   true,
		ReflexBlockMode: true,
	}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	ip := "192.168.1.200" // Legitimate resolver

	// Mix of normal and high-amp queries (legitimate pattern)
	blocked := 0
	for i := 0; i < 50; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)

		// 70% normal queries, 30% high-amp
		if i%10 < 7 {
			req.SetQuestion("example.com.", dns.TypeA)
		} else {
			req.SetQuestion("example.com.", dns.TypeDNSKEY)
		}

		mw := mock.NewWriter("udp", ip+":12345")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		if mw.Written() && mw.Rcode() == dns.RcodeRefused {
			blocked++
		}
	}

	// Should NOT block legitimate traffic
	assert.Equal(t, 0, blocked, "legitimate mixed traffic should not be blocked")
}

func TestServeDNS_TCPClearsReputation(t *testing.T) {
	cfg := &config.Config{
		ReflexEnabled:   true,
		ReflexBlockMode: true,
	}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	ip := "192.168.1.201"

	// First: suspicious UDP queries
	for i := 0; i < 20; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeDNSKEY)
		mw := mock.NewWriter("udp", ip+":12345")
		ch.Reset(mw, req)
		r.ServeDNS(context.Background(), ch)
	}

	// Then: TCP connection (proves real IP)
	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	mw := mock.NewWriter("tcp", ip+":12345")
	ch.Reset(mw, req)
	r.ServeDNS(context.Background(), ch)

	// Now UDP queries should be fine
	ch2 := middleware.NewChain([]middleware.Handler{})
	req2 := new(dns.Msg)
	req2.SetQuestion("example.com.", dns.TypeDNSKEY)
	mw2 := mock.NewWriter("udp", ip+":12345")
	ch2.Reset(mw2, req2)
	r.ServeDNS(context.Background(), ch2)

	assert.False(t, mw2.Written(), "after TCP, UDP should not be blocked")
}

func TestServeDNS_LearningMode(t *testing.T) {
	cfg := &config.Config{
		ReflexEnabled:      true,
		ReflexBlockMode:    true,
		ReflexLearningMode: true,
	}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	ip := "203.0.113.102"

	// Simulate attack
	blocked := 0
	for i := 0; i < 50; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeDNSKEY)
		mw := mock.NewWriter("udp", ip+":12345")
		ch.Reset(mw, req)

		r.ServeDNS(context.Background(), ch)
		if mw.Written() && mw.Rcode() == dns.RcodeRefused {
			blocked++
		}
	}

	// Learning mode should NOT block
	assert.Equal(t, 0, blocked, "learning mode should not block")
}

func TestClose(t *testing.T) {
	cfg := &config.Config{ReflexEnabled: true}
	r := New(cfg)

	err := r.Close()
	assert.NoError(t, err)
}

func BenchmarkServeDNS_NormalQuery(b *testing.B) {
	cfg := &config.Config{ReflexEnabled: true, ReflexBlockMode: true}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		mw := mock.NewWriter("udp", "192.168.1.100:12345")
		ch.Reset(mw, req)
		r.ServeDNS(context.Background(), ch)
	}
}

func BenchmarkServeDNS_HighAmpQuery(b *testing.B) {
	cfg := &config.Config{ReflexEnabled: true, ReflexBlockMode: true}
	r := New(cfg)
	defer func() { _ = r.Close() }()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeDNSKEY)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ch := middleware.NewChain([]middleware.Handler{})
		mw := mock.NewWriter("udp", "192.168.1.100:12345")
		ch.Reset(mw, req)
		r.ServeDNS(context.Background(), ch)
	}
}
