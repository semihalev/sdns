package metrics

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func Test_Metrics(t *testing.T) {
	middleware.Register("metrics", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(&config.Config{})

	m := middleware.Get("metrics").(*Metrics)

	assert.Equal(t, "metrics", m.Name())

	ch := middleware.NewChain([]middleware.Handler{})

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	ch.Reset(mw, req)

	m.ServeDNS(context.Background(), ch)
	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	_ = ch.Writer.WriteMsg(req)
	assert.Equal(t, true, ch.Writer.Written())

	m.ServeDNS(context.Background(), ch)
	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())
}

func Test_DomainMetrics(t *testing.T) {
	// Test with domain metrics enabled
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 3,
	}

	m := New(cfg)
	assert.NotNil(t, m.domainQueries)
	assert.True(t, m.domainMetricsEnabled)
	assert.Equal(t, 3, m.domainMetricsLimit)

	ch := middleware.NewChain([]middleware.Handler{})

	// Test multiple domains
	domains := []string{"test1.com.", "test2.com.", "test3.com.", "test4.com."}

	for _, domain := range domains {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// Check that only 3 domains are tracked due to limit
	assert.Equal(t, int32(3), atomic.LoadInt32(&m.domainCount))
}

func Test_DomainMetrics_Disabled(t *testing.T) {
	// Test with domain metrics disabled
	cfg := &config.Config{
		DomainMetrics: false,
	}

	m := New(cfg)
	assert.Nil(t, m.domainQueries)
	assert.False(t, m.domainMetricsEnabled)

	ch := middleware.NewChain([]middleware.Handler{})
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	ch.Reset(mw, req)

	_ = ch.Writer.WriteMsg(req)
	m.ServeDNS(context.Background(), ch)

	// No domains should be tracked
	assert.Equal(t, int32(0), atomic.LoadInt32(&m.domainCount))
}

func Test_DomainMetrics_Unlimited(t *testing.T) {
	// Test with unlimited domain metrics
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 0, // unlimited
	}

	m := New(cfg)
	assert.NotNil(t, m.domainQueries)
	assert.Equal(t, 0, m.domainMetricsLimit)

	ch := middleware.NewChain([]middleware.Handler{})

	// Test many domains
	for i := 0; i < 10; i++ {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("test%d.com.", i), dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// All domains should be tracked (unlimited)
	assert.Equal(t, int32(10), atomic.LoadInt32(&m.domainCount))
}

func Test_DomainMetrics_TopDomains(t *testing.T) {
	// Test that we keep top domains and remove low-count ones
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 5,
	}

	m := New(cfg)
	// Set last cleanup to past to allow immediate cleanup
	m.lastCleanup = time.Now().Add(-10 * time.Minute)

	ch := middleware.NewChain([]middleware.Handler{})

	// Create domains with different query counts
	domains := []struct {
		name  string
		count int
	}{
		{"popular1.com.", 100},
		{"popular2.com.", 80},
		{"popular3.com.", 60},
		{"popular4.com.", 40},
		{"popular5.com.", 20},
		{"unpopular.com.", 1},
	}

	// Query each domain the specified number of times
	for _, d := range domains {
		for i := 0; i < d.count; i++ {
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(d.name, dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Should have tracked first 5 domains
	assert.Equal(t, int32(5), atomic.LoadInt32(&m.domainCount))

	// The unpopular domain should have triggered cleanup but still not be tracked
	_, exists := m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("unpopular.com.", ".")))
	assert.False(t, exists)
}

func Test_DomainMetrics_EvictionAfterCleanup(t *testing.T) {
	// Test that the system maintains the configured limit
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 3,
	}

	m := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{})

	// Fill up to limit with domains
	for i := 1; i <= 3; i++ {
		for j := 0; j < 10*i; j++ { // Different query counts
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(fmt.Sprintf("domain%d.com.", i), dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Should have 3 domains
	assert.Equal(t, int32(3), atomic.LoadInt32(&m.domainCount))

	// Try to add a new domain when at limit - it should not be tracked
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("newdomain.com.", dns.TypeA)
	ch.Reset(mw, req)
	_ = ch.Writer.WriteMsg(req)
	m.ServeDNS(context.Background(), ch)

	// Should still have 3 domains (limit enforced)
	assert.Equal(t, int32(3), atomic.LoadInt32(&m.domainCount))

	// The new domain should not be tracked
	_, exists := m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("newdomain.com.", ".")))
	assert.False(t, exists, "newdomain.com should not be tracked when at limit")

	// Original domains should still be tracked
	for i := 1; i <= 3; i++ {
		domain := fmt.Sprintf("domain%d.com", i)
		_, exists := m.domainTracker.Load(strings.ToLower(domain))
		assert.True(t, exists, fmt.Sprintf("%s should still be tracked", domain))
	}
}

func Test_DomainMetrics_CleanupKeepsTopDomains(t *testing.T) {
	// Test that cleanup keeps top domains when going over limit
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 3,
	}

	m := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{})

	// Add domains up to limit - 1
	domains := []struct {
		name  string
		count int
	}{
		{"domain1.com.", 10},
		{"domain2.com.", 20},
	}

	for _, d := range domains {
		for i := 0; i < d.count; i++ {
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(d.name, dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Should have 2 domains
	assert.Equal(t, int32(2), atomic.LoadInt32(&m.domainCount))

	// Add two more domains to go over limit
	newDomains := []struct {
		name  string
		count int
	}{
		{"domain3.com.", 30},
		{"domain4.com.", 5}, // This one has fewer queries
	}

	for _, d := range newDomains {
		for i := 0; i < d.count; i++ {
			mw := mock.NewWriter("udp", "127.0.0.1:0")
			req := new(dns.Msg)
			req.SetQuestion(d.name, dns.TypeA)
			ch.Reset(mw, req)

			_ = ch.Writer.WriteMsg(req)
			m.ServeDNS(context.Background(), ch)
		}
	}

	// Force cleanup
	m.lastCleanup = time.Now().Add(-10 * time.Minute)
	m.maybeCleanupDomains()

	// Should be back to limit
	assert.LessOrEqual(t, int(atomic.LoadInt32(&m.domainCount)), 3)

	// Top 3 domains should be tracked (domain3, domain2, domain1)
	_, exists := m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain3.com.", ".")))
	assert.True(t, exists, "domain3.com (30 queries) should be tracked")

	_, exists = m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain2.com.", ".")))
	assert.True(t, exists, "domain2.com (20 queries) should be tracked")

	_, exists = m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain1.com.", ".")))
	assert.True(t, exists, "domain1.com (10 queries) should be tracked")

	// Lowest count domain should be evicted
	_, exists = m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("domain4.com.", ".")))
	assert.False(t, exists, "domain4.com (5 queries) should have been evicted")
}

func Test_DomainMetrics_SingleLabelFiltering(t *testing.T) {
	// Test that single-label domains are filtered out
	cfg := &config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 10,
	}

	m := New(cfg)
	ch := middleware.NewChain([]middleware.Handler{})

	// Test various single-label domains that should be ignored
	singleLabelDomains := []string{
		"com.",
		"localhost.",
		"local.",
		"test.",
		"arpa.",
	}

	for _, domain := range singleLabelDomains {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// No single-label domains should be tracked
	assert.Equal(t, int32(0), atomic.LoadInt32(&m.domainCount))

	// Test multi-label domains that should be tracked
	multiLabelDomains := []string{
		"example.com.",
		"subdomain.example.com.",
		"deep.subdomain.example.com.",
		"test.local.",
	}

	for _, domain := range multiLabelDomains {
		mw := mock.NewWriter("udp", "127.0.0.1:0")
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)
		ch.Reset(mw, req)

		_ = ch.Writer.WriteMsg(req)
		m.ServeDNS(context.Background(), ch)
	}

	// All multi-label domains should be tracked
	assert.Equal(t, int32(len(multiLabelDomains)), atomic.LoadInt32(&m.domainCount))

	// Verify each multi-label domain is tracked
	for _, domain := range multiLabelDomains {
		normalized := strings.ToLower(strings.TrimSuffix(domain, "."))
		_, exists := m.domainTracker.Load(normalized)
		assert.True(t, exists, fmt.Sprintf("%s should be tracked", domain))
	}
}
